// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Fixed-storage Linux device-tree construction for qualified reference VMs.

pub mod io;
mod riscv64;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;
const HEADER_SIZE: usize = 40;
const RESERVATION_SIZE: usize = 16;
const GIC_PHANDLE: u32 = 0xffff_0001;
const GIC_DISTRIBUTOR_BASE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GIC_DISTRIBUTOR_BASE;
const GIC_DISTRIBUTOR_SIZE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GIC_DISTRIBUTOR_SIZE;
const GIC_REDISTRIBUTOR_BASE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GIC_REDISTRIBUTOR_BASE;
const GIC_REDISTRIBUTOR_SIZE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GIC_REDISTRIBUTOR_SIZE;
const UART_BASE: u64 = hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_UART_BASE;
const UART_SIZE: u64 = hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_UART_SIZE;
const UART_SPI: u32 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_UART_INTERRUPT as u32 - 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    OutputTooSmall,
    StructureTooSmall,
    StringsTooSmall,
    InvalidInput,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64LinuxBoot<'arguments> {
    pub memory_base: u64,
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub gic_version: u32,
    pub initramfs: Option<(u64, u64)>,
    pub boot_arguments: &'arguments str,
}

/// Hardware facts obtained from the Native creation lease, never inferred from
/// the image container or copied from the host's device tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestHardwareMetadata {
    Aarch64 {
        gic_version: u32,
    },
    Riscv64 {
        counter_frequency_hz: u64,
        riscv_isa: u64,
    },
}

impl GuestHardwareMetadata {
    pub fn validate_for(self, plan: &crate::linux::BootPlan) -> Result<(), Error> {
        match (self, plan.architecture(), plan.platform_profile()) {
            (
                Self::Aarch64 { gic_version: 2 | 3 },
                crate::Architecture::Aarch64,
                crate::PlatformProfile::Aarch64Reference,
            ) => Ok(()),
            (
                Self::Riscv64 {
                    counter_frequency_hz,
                    riscv_isa,
                },
                crate::Architecture::Riscv64,
                crate::PlatformProfile::Riscv64Reference,
            ) if counter_frequency_hz > 0
                && counter_frequency_hz <= u64::from(u32::MAX)
                && riscv_isa & riscv64::ISA == riscv64::ISA =>
            {
                Ok(())
            }
            _ => Err(Error::InvalidInput),
        }
    }
}

/// Encodes the selected, already validated boot plan into caller-owned buffers.
pub fn build_linux(
    plan: &crate::linux::BootPlan,
    boot_arguments: &str,
    hardware: GuestHardwareMetadata,
    structure: &mut [u8],
    strings: &mut [u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    hardware.validate_for(plan)?;
    if boot_arguments.as_bytes().contains(&0)
        || boot_arguments.len() > crate::MAX_BOOT_ARGUMENT_BYTES
    {
        return Err(Error::InvalidInput);
    }
    match hardware {
        GuestHardwareMetadata::Aarch64 { gic_version } => build_aarch64_linux(
            Aarch64LinuxBoot {
                memory_base: plan.memory_base(),
                memory_size: plan.memory_size(),
                vcpu_count: plan.vcpu_count(),
                gic_version,
                initramfs: plan.initramfs().map(|range| (range.start(), range.end())),
                boot_arguments,
            },
            structure,
            strings,
            output,
        ),
        GuestHardwareMetadata::Riscv64 {
            counter_frequency_hz,
            ..
        } => riscv64::build(
            plan,
            boot_arguments,
            counter_frequency_hz as u32,
            structure,
            strings,
            output,
        ),
    }
}

/// Builds a complete Linux-format DTB into caller-owned fixed storage.
pub fn build_aarch64_linux(
    boot: Aarch64LinuxBoot<'_>,
    structure: &mut [u8],
    strings: &mut [u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    build_aarch64_linux_with_io(boot, io::IoDevices::empty(), structure, strings, output)
}

/// Builds the reference tree plus explicitly admitted storage/control devices.
/// Physical DMA ranges are supplied by Native device authority, never inferred
/// from a guest address or copied from host firmware.
pub fn build_aarch64_linux_with_io(
    boot: Aarch64LinuxBoot<'_>,
    devices: io::IoDevices<'_>,
    structure: &mut [u8],
    strings: &mut [u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    devices.validate(boot)?;
    let memory_end = boot
        .memory_base
        .checked_add(boot.memory_size)
        .ok_or(Error::AddressOverflow)?;
    if boot.memory_size == 0
        || !(1..=hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_MAX_VCPUS)
            .contains(&u64::from(boot.vcpu_count))
        || !matches!(boot.gic_version, 2 | 3)
        || boot.boot_arguments.as_bytes().contains(&0)
        || boot.initramfs.is_some_and(|(start, end)| {
            start < boot.memory_base || start >= end || end > memory_end
        })
    {
        return Err(Error::InvalidInput);
    }
    let mut builder = Builder::new(structure, strings);
    builder.begin_node("")?;
    builder.property_u32("#address-cells", 2)?;
    builder.property_u32("#size-cells", 2)?;
    builder.property_u32("interrupt-parent", GIC_PHANDLE)?;
    builder.property_string("compatible", "hyper,virtual-machine")?;
    builder.property_string("model", "HypeR AArch64 virtual machine")?;

    builder.begin_node("chosen")?;
    builder.property_string("bootargs", boot.boot_arguments)?;
    builder.property_string("stdout-path", "/uart@9000000")?;
    if let Some((start, end)) = boot.initramfs {
        builder.property_u64("linux,initrd-start", start)?;
        builder.property_u64("linux,initrd-end", end)?;
    }
    builder.end_node()?;

    builder.begin_node("aliases")?;
    builder.property_string("serial0", "/uart@9000000")?;
    builder.end_node()?;

    let mut node_name = [0u8; 32];
    let memory_name = hex_node_name("memory@", boot.memory_base, &mut node_name)?;
    builder.begin_node(memory_name)?;
    builder.property_string("device_type", "memory")?;
    builder.property_u64_pair("reg", boot.memory_base, boot.memory_size)?;
    builder.end_node()?;

    builder.begin_node("cpus")?;
    builder.property_u32("#address-cells", 2)?;
    builder.property_u32("#size-cells", 0)?;
    for index in 0..boot.vcpu_count {
        let cpu_name = hex_node_name("cpu@", u64::from(index), &mut node_name)?;
        builder.begin_node(cpu_name)?;
        builder.property_string("device_type", "cpu")?;
        builder.property_string("compatible", "arm,armv8")?;
        builder.property_string("enable-method", "psci")?;
        builder.property_u64("reg", u64::from(index))?;
        builder.end_node()?;
    }
    builder.end_node()?;

    builder.begin_node("psci")?;
    builder.property_string_list("compatible", &["arm,psci-1.0", "arm,psci-0.2"])?;
    builder.property_string("method", "hvc")?;
    builder.end_node()?;

    builder.begin_node("intc@8000000")?;
    builder.property_empty("interrupt-controller")?;
    builder.property_u32("#interrupt-cells", 3)?;
    builder.property_string(
        "compatible",
        if boot.gic_version == 2 {
            "arm,cortex-a15-gic"
        } else {
            "arm,gic-v3"
        },
    )?;
    builder.property_u32("phandle", GIC_PHANDLE)?;
    builder.property_cells(
        "reg",
        &[
            0,
            GIC_DISTRIBUTOR_BASE as u32,
            0,
            if boot.gic_version == 2 {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GICV2_DISTRIBUTOR_SIZE
                    as u32
            } else {
                GIC_DISTRIBUTOR_SIZE as u32
            },
            0,
            if boot.gic_version == 2 {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GICV2_CPU_BASE as u32
            } else {
                GIC_REDISTRIBUTOR_BASE as u32
            },
            0,
            if boot.gic_version == 2 {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GICV2_CPU_SIZE as u32
            } else {
                GIC_REDISTRIBUTOR_SIZE as u32 * boot.vcpu_count
            },
        ],
    )?;
    if let Some(pci) = devices.pci {
        pci.append_msi(&mut builder)?;
    } else {
        builder.property_u32("#address-cells", 0)?;
    }
    builder.end_node()?;

    builder.begin_node("timer")?;
    builder.property_string("compatible", "arm,armv8-timer")?;
    builder.property_empty("always-on")?;
    // GICv2's PPI flags carry the CPU target mask; each guest CPU owns its
    // banked timer interrupts. GICv3 ignores that legacy mask field.
    let timer_flags = if boot.gic_version == 2 {
        4 | (((1u32 << boot.vcpu_count) - 1) << 8)
    } else {
        4
    };
    builder.property_cells(
        "interrupts",
        &[
            1,
            13,
            timer_flags,
            1,
            14,
            timer_flags,
            1,
            11,
            timer_flags,
            1,
            10,
            timer_flags,
        ],
    )?;
    builder.end_node()?;

    builder.begin_node("uart@9000000")?;
    builder.property_string("compatible", "arm,sbsa-uart")?;
    builder.property_u64_pair("reg", UART_BASE, UART_SIZE)?;
    builder.property_cells("interrupts", &[0, UART_SPI, 4])?;
    builder.property_u32(
        "current-speed",
        hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_UART_BAUD as u32,
    )?;
    builder.end_node()?;

    devices.append(&mut builder, boot)?;
    builder.end_node()?;
    builder.finish(output)
}

struct Builder<'storage> {
    structure: &'storage mut [u8],
    structure_length: usize,
    strings: &'storage mut [u8],
    strings_length: usize,
}

impl<'storage> Builder<'storage> {
    const fn new(structure: &'storage mut [u8], strings: &'storage mut [u8]) -> Self {
        Self {
            structure,
            structure_length: 0,
            strings,
            strings_length: 0,
        }
    }

    fn begin_node(&mut self, name: &str) -> Result<(), Error> {
        self.push_u32(FDT_BEGIN_NODE)?;
        self.push(name.as_bytes())?;
        self.push(&[0])?;
        self.pad()
    }

    fn end_node(&mut self) -> Result<(), Error> {
        self.push_u32(FDT_END_NODE)
    }

    fn property(&mut self, name: &str, value: &[u8]) -> Result<(), Error> {
        let name_offset = self.name_offset(name)?;
        self.push_u32(FDT_PROP)?;
        self.push_u32(u32::try_from(value.len()).map_err(|_| Error::AddressOverflow)?)?;
        self.push_u32(name_offset)?;
        self.push(value)?;
        self.pad()
    }

    fn property_empty(&mut self, name: &str) -> Result<(), Error> {
        self.property(name, &[])
    }

    fn property_u32(&mut self, name: &str, value: u32) -> Result<(), Error> {
        self.property(name, &value.to_be_bytes())
    }

    fn property_u64(&mut self, name: &str, value: u64) -> Result<(), Error> {
        self.property_cells(name, &[(value >> 32) as u32, value as u32])
    }

    fn property_u64_pair(&mut self, name: &str, first: u64, second: u64) -> Result<(), Error> {
        self.property_cells(
            name,
            &[
                (first >> 32) as u32,
                first as u32,
                (second >> 32) as u32,
                second as u32,
            ],
        )
    }

    fn property_cells(&mut self, name: &str, values: &[u32]) -> Result<(), Error> {
        let name_offset = self.name_offset(name)?;
        let byte_length = values.len().checked_mul(4).ok_or(Error::AddressOverflow)?;
        self.push_u32(FDT_PROP)?;
        self.push_u32(u32::try_from(byte_length).map_err(|_| Error::AddressOverflow)?)?;
        self.push_u32(name_offset)?;
        for value in values {
            self.push(&value.to_be_bytes())?;
        }
        self.pad()
    }

    fn property_string(&mut self, name: &str, value: &str) -> Result<(), Error> {
        let name_offset = self.name_offset(name)?;
        let length = value.len().checked_add(1).ok_or(Error::AddressOverflow)?;
        self.push_u32(FDT_PROP)?;
        self.push_u32(u32::try_from(length).map_err(|_| Error::AddressOverflow)?)?;
        self.push_u32(name_offset)?;
        self.push(value.as_bytes())?;
        self.push(&[0])?;
        self.pad()
    }

    fn property_string_list(&mut self, name: &str, values: &[&str]) -> Result<(), Error> {
        let name_offset = self.name_offset(name)?;
        let length = values
            .iter()
            .try_fold(0usize, |total, value| {
                total.checked_add(value.len().checked_add(1)?)
            })
            .ok_or(Error::AddressOverflow)?;
        self.push_u32(FDT_PROP)?;
        self.push_u32(u32::try_from(length).map_err(|_| Error::AddressOverflow)?)?;
        self.push_u32(name_offset)?;
        for value in values {
            self.push(value.as_bytes())?;
            self.push(&[0])?;
        }
        self.pad()
    }

    fn name_offset(&mut self, name: &str) -> Result<u32, Error> {
        let mut offset = 0usize;
        while offset < self.strings_length {
            let tail = self
                .strings
                .get(offset..self.strings_length)
                .ok_or(Error::StringsTooSmall)?;
            let length = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(Error::StringsTooSmall)?;
            if tail.get(..length) == Some(name.as_bytes()) {
                return u32::try_from(offset).map_err(|_| Error::AddressOverflow);
            }
            offset = offset
                .checked_add(length + 1)
                .ok_or(Error::AddressOverflow)?;
        }
        let result = u32::try_from(self.strings_length).map_err(|_| Error::AddressOverflow)?;
        let end = self
            .strings_length
            .checked_add(name.len() + 1)
            .ok_or(Error::AddressOverflow)?;
        let destination = self
            .strings
            .get_mut(self.strings_length..end)
            .ok_or(Error::StringsTooSmall)?;
        let name_end = name.len();
        destination
            .get_mut(..name_end)
            .ok_or(Error::StringsTooSmall)?
            .copy_from_slice(name.as_bytes());
        *destination
            .get_mut(name_end)
            .ok_or(Error::StringsTooSmall)? = 0;
        self.strings_length = end;
        Ok(result)
    }

    fn push_u32(&mut self, value: u32) -> Result<(), Error> {
        self.push(&value.to_be_bytes())
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .structure_length
            .checked_add(bytes.len())
            .ok_or(Error::AddressOverflow)?;
        self.structure
            .get_mut(self.structure_length..end)
            .ok_or(Error::StructureTooSmall)?
            .copy_from_slice(bytes);
        self.structure_length = end;
        Ok(())
    }

    fn pad(&mut self) -> Result<(), Error> {
        while !self.structure_length.is_multiple_of(4) {
            self.push(&[0])?;
        }
        Ok(())
    }

    fn finish(mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.push_u32(FDT_END)?;
        let structure_offset = HEADER_SIZE + RESERVATION_SIZE;
        let strings_offset = structure_offset
            .checked_add(self.structure_length)
            .ok_or(Error::AddressOverflow)?;
        let total_size = strings_offset
            .checked_add(self.strings_length)
            .ok_or(Error::AddressOverflow)?;
        let output = output.get_mut(..total_size).ok_or(Error::OutputTooSmall)?;
        let values = [
            FDT_MAGIC,
            u32::try_from(total_size).map_err(|_| Error::AddressOverflow)?,
            u32::try_from(structure_offset).map_err(|_| Error::AddressOverflow)?,
            u32::try_from(strings_offset).map_err(|_| Error::AddressOverflow)?,
            HEADER_SIZE as u32,
            17,
            16,
            0,
            u32::try_from(self.strings_length).map_err(|_| Error::AddressOverflow)?,
            u32::try_from(self.structure_length).map_err(|_| Error::AddressOverflow)?,
        ];
        for (chunk, value) in output[..HEADER_SIZE].chunks_exact_mut(4).zip(values) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        output[HEADER_SIZE..structure_offset].fill(0);
        output[structure_offset..strings_offset]
            .copy_from_slice(&self.structure[..self.structure_length]);
        output[strings_offset..total_size].copy_from_slice(&self.strings[..self.strings_length]);
        Ok(total_size)
    }
}

fn hex_node_name<'buffer>(
    prefix: &str,
    value: u64,
    output: &'buffer mut [u8],
) -> Result<&'buffer str, Error> {
    if prefix.len() >= output.len() {
        return Err(Error::OutputTooSmall);
    }
    output
        .get_mut(..prefix.len())
        .ok_or(Error::OutputTooSmall)?
        .copy_from_slice(prefix.as_bytes());
    let digits = if value == 0 {
        1
    } else {
        ((u64::BITS - value.leading_zeros()) as usize).div_ceil(4)
    };
    let end = prefix
        .len()
        .checked_add(digits)
        .ok_or(Error::AddressOverflow)?;
    let destination = output
        .get_mut(prefix.len()..end)
        .ok_or(Error::OutputTooSmall)?;
    for (index, byte) in destination.iter_mut().enumerate() {
        let shift = (digits - index - 1) * 4;
        let nibble = ((value >> shift) & 0xf) as u8;
        *byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    core::str::from_utf8(&output[..end]).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::{Aarch64LinuxBoot, FDT_MAGIC, build_aarch64_linux};

    #[test]
    fn emits_gicv2_cpu_window_and_rejects_unknown_revision() -> Result<(), super::Error> {
        for version in [2, 3, 4] {
            let mut structure = [0; 8192];
            let mut strings = [0; 2048];
            let mut output = [0; 12288];
            let result = build_aarch64_linux(
                Aarch64LinuxBoot {
                    gic_version: version,
                    memory_base: 0x4000_0000,
                    memory_size: 0x0800_0000,
                    vcpu_count: 1,
                    initramfs: None,
                    boot_arguments: "console=ttyAMA0",
                },
                &mut structure,
                &mut strings,
                &mut output,
            );
            if version == 4 {
                assert_eq!(result, Err(super::Error::InvalidInput));
                continue;
            }
            let size = result?;
            let compatible: &[u8] = if version == 2 {
                b"arm,cortex-a15-gic\0"
            } else {
                b"arm,gic-v3\0"
            };
            assert!(
                output[..size]
                    .windows(compatible.len())
                    .any(|bytes| bytes == compatible)
            );
            if version == 2 {
                assert!(
                    output[..size]
                        .windows(8)
                        .any(|bytes| bytes == 0x0801_0000u64.to_be_bytes())
                );
            }
        }
        Ok(())
    }

    #[test]
    fn emits_all_smp_cpu_nodes_and_bounds_topology() -> Result<(), super::Error> {
        for version in [2, 3] {
            for count in [0, 1, 4, 8, 9] {
                let mut structure = [0; 8192];
                let mut strings = [0; 2048];
                let mut output = [0; 12288];
                let result = build_aarch64_linux(
                    Aarch64LinuxBoot {
                        gic_version: version,
                        memory_base: 0x4000_0000,
                        memory_size: 0x0800_0000,
                        vcpu_count: count,
                        initramfs: None,
                        boot_arguments: "",
                    },
                    &mut structure,
                    &mut strings,
                    &mut output,
                );
                if count == 0 || count > 8 {
                    assert_eq!(result, Err(super::Error::InvalidInput));
                    continue;
                }
                let size = result?;
                let bytes = &output[..size];
                assert_eq!(
                    bytes.windows(4).filter(|word| *word == b"cpu@").count(),
                    count as usize
                );
                if count == 8 {
                    assert!(bytes.windows(6).any(|word| word == b"cpu@7\0"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn builds_a_bounded_single_cpu_linux_tree() -> Result<(), super::Error> {
        let mut structure = [0u8; 8192];
        let mut strings = [0u8; 2048];
        let mut output = [0u8; 12 * 1024];
        let size = build_aarch64_linux(
            Aarch64LinuxBoot {
                gic_version: 3,
                memory_base: 0x4000_0000,
                memory_size: 128 * 1024 * 1024,
                vcpu_count: 1,
                initramfs: Some((0x4700_0000, 0x4780_0000)),
                boot_arguments: "console=ttyAMA0",
            },
            &mut structure,
            &mut strings,
            &mut output,
        )?;
        assert!(size < output.len());
        let mut word = [0u8; 4];
        word.copy_from_slice(&output[..4]);
        assert_eq!(u32::from_be_bytes(word), FDT_MAGIC);
        word.copy_from_slice(&output[4..8]);
        assert_eq!(u32::from_be_bytes(word) as usize, size);
        Ok(())
    }
}
