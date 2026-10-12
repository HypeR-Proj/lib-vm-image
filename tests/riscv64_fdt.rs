// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

extern crate std;
use super::Source;
use crate::guest_fdt::{self, GuestHardwareMetadata};
use std::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let array = bytes
        .get(offset..offset + 4)
        .ok_or("truncated word")?
        .try_into()
        .map_err(|_| "word")?;
    Ok(u32::from_be_bytes(array))
}
fn string_at(bytes: &[u8], offset: usize) -> Result<(&str, usize), &'static str> {
    let tail = bytes.get(offset..).ok_or("string offset")?;
    let length = tail
        .iter()
        .position(|value| *value == 0)
        .ok_or("missing terminator")?;
    Ok((
        core::str::from_utf8(&tail[..length]).map_err(|_| "invalid string")?,
        length + 1,
    ))
}

// Independent token reader checks node paths and encoded cells, rather than
// searching for matching strings that might belong to unrelated properties.
fn properties(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, &'static str> {
    if u32_at(bytes, 0)? != 0xd00d_feed {
        return Err("bad DTB magic");
    }
    let strings = u32_at(bytes, 12)? as usize;
    let mut at = u32_at(bytes, 8)? as usize;
    let end = at + u32_at(bytes, 36)? as usize;
    let mut nodes = Vec::new();
    let mut properties = BTreeMap::new();
    while at < end {
        let token = u32_at(bytes, at)?;
        at += 4;
        match token {
            1 => {
                let (name, length) = string_at(bytes, at)?;
                nodes.push(name.to_string());
                at = (at + length + 3) & !3;
            }
            2 => {
                nodes.pop().ok_or("unbalanced node")?;
            }
            3 => {
                let length = u32_at(bytes, at)? as usize;
                let name_offset = u32_at(bytes, at + 4)? as usize;
                at += 8;
                let (name, _) = string_at(bytes, strings + name_offset)?;
                let key = std::format!("{}/{name}", nodes.join("/"));
                let value = bytes
                    .get(at..at + length)
                    .ok_or("truncated property")?
                    .to_vec();
                if properties.insert(key, value).is_some() {
                    return Err("duplicate property");
                }
                at = (at + length + 3) & !3;
            }
            9 if nodes.is_empty() && at == end => return Ok(properties),
            _ => return Err("unexpected token"),
        }
    }
    Err("missing END")
}

const BASELINE: u64 = (1 << 9) - 1;
fn hardware(frequency: u64, isa: u64) -> GuestHardwareMetadata {
    GuestHardwareMetadata::Riscv64 {
        counter_frequency_hz: frequency,
        riscv_isa: isa,
    }
}

#[test]
fn dtb_describes_qualified_rv_cpu_clock_and_supervisor_plic_context() -> Result<(), &'static str> {
    let plan =
        crate::linux::validate_reference(&Source::valid(), Source::image()).map_err(|_| "plan")?;
    let mut structure = [0; 4096];
    let mut strings = [0; 2048];
    let mut output = [0; 8192];
    let size = guest_fdt::build_linux(
        &plan,
        "console=ttyS0",
        hardware(1_234_567, BASELINE),
        &mut structure,
        &mut strings,
        &mut output,
    )
    .map_err(|_| "build")?;
    assert_eq!(u32_at(&output, 4)? as usize, size);
    let values = properties(&output[..size])?;
    let value = |path| {
        values
            .get(path)
            .map(Vec::as_slice)
            .ok_or("missing property")
    };
    assert_eq!(
        value("/cpus/timebase-frequency")?,
        1_234_567u32.to_be_bytes()
    );
    assert_eq!(value("/cpus/cpu@0/reg")?, 0u32.to_be_bytes());
    assert_eq!(value("/cpus/cpu@0/mmu-type")?, b"riscv,sv39\0");
    assert_eq!(
        value("/cpus/cpu@0/riscv,isa")?,
        b"rv64imafdc_zicsr_zifencei_sstc\0"
    );
    assert_eq!(
        value("/cpus/cpu@0/riscv,isa-extensions")?,
        b"i\0m\0a\0f\0d\0c\0zicsr\0zifencei\0sstc\0"
    );
    let contexts = value("/soc/interrupt-controller@c000000/interrupts-extended")?;
    assert_eq!(
        [
            u32_at(contexts, 0)?,
            u32_at(contexts, 4)?,
            u32_at(contexts, 8)?,
            u32_at(contexts, 12)?
        ],
        [1, u32::MAX, 1, 9]
    );
    assert_eq!(
        value("/soc/interrupt-controller@c000000/#address-cells")?,
        0u32.to_be_bytes()
    );
    assert_eq!(
        value("/soc/serial@10000000/interrupt-parent")?,
        2u32.to_be_bytes()
    );
    assert_eq!(value("/soc/serial@10000000/compatible")?, b"ns16550a\0");
    assert_eq!(
        value("/chosen/stdout-path")?,
        b"/soc/serial@10000000:115200n8\0"
    );
    Ok(())
}

#[test]
fn additive_unknown_isa_does_not_leak_into_guest_tree() -> Result<(), &'static str> {
    let plan =
        crate::linux::validate_reference(&Source::valid(), Source::image()).map_err(|_| "plan")?;
    let mut structure = [0; 4096];
    let mut strings = [0; 2048];
    let mut first = [0; 8192];
    let mut second = [0; 8192];
    let a = guest_fdt::build_linux(
        &plan,
        "",
        hardware(123, BASELINE),
        &mut structure,
        &mut strings,
        &mut first,
    )
    .map_err(|_| "first")?;
    let b = guest_fdt::build_linux(
        &plan,
        "",
        hardware(123, BASELINE | (1 << 63)),
        &mut structure,
        &mut strings,
        &mut second,
    )
    .map_err(|_| "second")?;
    assert_eq!(a, b);
    assert_eq!(first[..a], second[..b]);
    Ok(())
}

#[test]
fn rejects_missing_capabilities_bad_clock_and_small_storage() -> Result<(), &'static str> {
    let plan =
        crate::linux::validate_reference(&Source::valid(), Source::image()).map_err(|_| "plan")?;
    for frequency in [0, u64::from(u32::MAX) + 1] {
        assert_eq!(
            hardware(frequency, BASELINE).validate_for(&plan),
            Err(guest_fdt::Error::InvalidInput)
        );
    }
    for bit in 0..9 {
        assert_eq!(
            hardware(100, BASELINE & !(1 << bit)).validate_for(&plan),
            Err(guest_fdt::Error::InvalidInput)
        );
    }
    assert_eq!(
        GuestHardwareMetadata::Aarch64 { gic_version: 3 }.validate_for(&plan),
        Err(guest_fdt::Error::InvalidInput)
    );
    let mut structure = [0; 4096];
    let mut strings = [0; 2048];
    let mut output = [0; 8192];
    assert_eq!(
        guest_fdt::build_linux(
            &plan,
            "",
            hardware(100, BASELINE),
            &mut [],
            &mut strings,
            &mut output
        ),
        Err(guest_fdt::Error::StructureTooSmall)
    );
    assert_eq!(
        guest_fdt::build_linux(
            &plan,
            "",
            hardware(100, BASELINE),
            &mut structure,
            &mut [],
            &mut output
        ),
        Err(guest_fdt::Error::StringsTooSmall)
    );
    assert_eq!(
        guest_fdt::build_linux(
            &plan,
            "",
            hardware(100, BASELINE),
            &mut structure,
            &mut strings,
            &mut []
        ),
        Err(guest_fdt::Error::OutputTooSmall)
    );
    Ok(())
}

#[test]
fn shared_arm_plan_preserves_existing_dtb_bytes() -> Result<(), &'static str> {
    let mut source = Source::valid();
    source.0[8..16].copy_from_slice(&0x80000u64.to_le_bytes());
    source.0[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    let mut image = Source::image();
    image.architecture = crate::Architecture::Aarch64;
    image.platform_profile = crate::PlatformProfile::Aarch64Reference;
    image.kernel.load_address = 0x4008_0000;
    image.kernel.entry_address = image.kernel.load_address;
    let plan = crate::linux::validate_reference(&source, image).map_err(|_| "plan")?;
    assert_eq!(plan.bootstrap_arguments(), [0x4001_0000, 0, 0, 0]);
    let mut structure = [0; 4096];
    let mut strings = [0; 2048];
    let mut first = [0; 8192];
    let mut second = [0; 8192];
    let a = guest_fdt::build_linux(
        &plan,
        "test",
        GuestHardwareMetadata::Aarch64 { gic_version: 3 },
        &mut structure,
        &mut strings,
        &mut first,
    )
    .map_err(|_| "shared")?;
    let b = guest_fdt::build_aarch64_linux(
        guest_fdt::Aarch64LinuxBoot {
            gic_version: 3,
            memory_base: plan.memory_base(),
            memory_size: plan.memory_size(),
            vcpu_count: 1,
            initramfs: None,
            boot_arguments: "test",
        },
        &mut structure,
        &mut strings,
        &mut second,
    )
    .map_err(|_| "old")?;
    assert_eq!(first[..a], second[..b]);
    Ok(())
}
