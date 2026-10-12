// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! A single admitted PCI function behind generic ECAM and `GICv2m` interfaces.

use super::{
    Aarch64LinuxBoot, Builder, Error, FirmwareNode, IoDevices, MmioDevice, MmioWindow, firmware,
    hex_node_name,
};

const MSI_PHANDLE: u32 = 0xffff_0180;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciBar {
    pub index: u32,
    pub window: MmioWindow,
    pub bus_address: u64,
    pub memory64: bool,
    pub prefetchable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciHost<'a> {
    pub aperture: MmioWindow,
    pub ecam: MmioWindow,
    pub msi: MmioWindow,
    /// Full GIC INTID of the first MSI, not the SPI-relative DT encoding.
    pub interrupt_base: u32,
    pub interrupt_count: u32,
    pub bars: &'a [PciBar],
    /// Admitted physical-to-device DMA translation, not guest RAM ownership.
    pub dma_bus_offset: u64,
    /// Board firmware projected into PCI bus address space by the caller.
    pub nodes: &'a [FirmwareNode<'a>],
}

impl PciHost<'_> {
    pub(super) fn validate(
        self,
        io: IoDevices<'_>,
        boot: Aarch64LinuxBoot<'_>,
    ) -> Result<(), Error> {
        let aperture_end = self
            .aperture
            .base
            .checked_add(self.aperture.size)
            .ok_or(Error::AddressOverflow)?;
        let irq_end = self
            .interrupt_base
            .checked_add(self.interrupt_count)
            .ok_or(Error::AddressOverflow)?;
        if io.dma_ranges.is_empty()
            || self.aperture.size != hyper_abi::HYPER_NATIVE_DEVICE_PCI_APERTURE_SIZE
            || !self.aperture.base.is_multiple_of(self.aperture.size)
            || self.aperture.base < 0x0b00_0000
            || aperture_end > 0x0c00_0000
            || !(1..=64).contains(&self.interrupt_count)
            || !super::device_irq(self.interrupt_base)
            || irq_end
                > hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_INTERRUPT_COUNT as u32
            || !self.dma_bus_offset.is_multiple_of(4096)
            || self.bars.is_empty()
            || self.bars.len() > 6
            || self.ecam
                != (MmioWindow {
                    base: self.aperture.base,
                    size: 0x10_0000,
                })
            || self.msi
                != (MmioWindow {
                    base: self.aperture.base + 0x10_0000,
                    size: 4096,
                })
        {
            return Err(Error::InvalidInput);
        }
        let check_memory = |base: u64, size: u64| -> Result<(), Error> {
            let end = base.checked_add(size).ok_or(Error::AddressOverflow)?;
            if super::overlaps(base, end, self.aperture.base, aperture_end) {
                Err(Error::InvalidInput)
            } else {
                Ok(())
            }
        };
        check_memory(boot.memory_base, boot.memory_size)?;
        if let Some(shared) = io.shared_memory {
            check_memory(shared.base, shared.size)?;
        }
        let check_device = |device: MmioDevice| -> Result<(), Error> {
            check_memory(device.base, device.size)?;
            if (self.interrupt_base..irq_end).contains(&device.irq) {
                Err(Error::InvalidInput)
            } else {
                Ok(())
            }
        };
        for device in [io.storage_node(), io.network, io.mailbox, io.notification]
            .into_iter()
            .flatten()
        {
            check_device(device)?;
        }
        for client in io.clients {
            check_memory(client.shared_memory.base, client.shared_memory.size)?;
            for device in [
                Some(client.mailbox),
                client.notification,
                client.network_notification,
            ]
            .into_iter()
            .flatten()
            {
                check_device(device)?;
            }
        }
        if let Some(sdhci) = io.sdhci {
            for window in [
                sdhci.config,
                sdhci.main_pinctrl,
                sdhci.aon_pinctrl,
                sdhci.aon_gpio,
            ] {
                check_memory(window.base, window.size)?;
            }
        }
        let mut occupied = 0u8;
        for (index, bar) in self.bars.iter().enumerate() {
            let size = bar.window.size;
            let end = bar
                .window
                .base
                .checked_add(size)
                .ok_or(Error::AddressOverflow)?;
            let bus_end = bar
                .bus_address
                .checked_add(size)
                .ok_or(Error::AddressOverflow)?;
            if bar.index >= 6
                || (bar.memory64 && bar.index == 5)
                || size < 16
                || !size.is_power_of_two()
                || !bar.window.base.is_multiple_of(size)
                || !bar.bus_address.is_multiple_of(size)
                || bar.window.base < self.aperture.base + 0x20_0000
                || end > aperture_end
                || bar.bus_address != bar.window.base - self.aperture.base
                || (!bar.memory64 && bus_end > 1u64 << 32)
                || self.bars[..index].iter().any(|other| {
                    super::overlaps(
                        bar.window.base,
                        end,
                        other.window.base,
                        other.window.base + other.window.size,
                    )
                })
            {
                return Err(Error::InvalidInput);
            }
            let mask = if bar.memory64 { 3 } else { 1 } << bar.index;
            if occupied & mask != 0 {
                return Err(Error::InvalidInput);
            }
            occupied |= mask;
        }
        for range in io.dma_ranges {
            range
                .dma_base
                .checked_add(self.dma_bus_offset)
                .and_then(|base| base.checked_add(range.size))
                .ok_or(Error::AddressOverflow)?;
        }
        firmware::validate(self.nodes)
    }

    pub(in crate::guest_fdt) fn append_msi(self, builder: &mut Builder<'_>) -> Result<(), Error> {
        builder.property_u32("#address-cells", 2)?;
        builder.property_u32("#size-cells", 2)?;
        builder.property_empty("ranges")?;
        let mut name = [0; 64];
        builder.begin_node(hex_node_name("msi-controller@", self.msi.base, &mut name)?)?;
        builder.property_string("compatible", "arm,gic-v2m-frame")?;
        builder.property_u64_pair("reg", self.msi.base, self.msi.size)?;
        builder.property_empty("msi-controller")?;
        builder.property_u32("#msi-cells", 0)?;
        builder.property_u32("phandle", MSI_PHANDLE)?;
        builder.property_u32("arm,msi-base-spi", self.interrupt_base)?;
        builder.property_u32("arm,msi-num-spis", self.interrupt_count)?;
        builder.end_node()
    }

    pub(super) fn append(self, builder: &mut Builder<'_>, io: IoDevices<'_>) -> Result<(), Error> {
        let mut name = [0; 64];
        builder.begin_node(hex_node_name("pcie@", self.ecam.base, &mut name)?)?;
        builder.property_string("compatible", "pci-host-ecam-generic")?;
        builder.property_string("device_type", "pci")?;
        builder.property_u32("#address-cells", 3)?;
        builder.property_u32("#size-cells", 2)?;
        builder.property_u32("#interrupt-cells", 1)?;
        builder.property_u64_pair("reg", self.ecam.base, self.ecam.size)?;
        builder.property_cells("bus-range", &[0, 0])?;
        builder.property_u32("msi-parent", MSI_PHANDLE)?;
        let mut cells = [0; 6 * 7];
        for (bar, cells) in self.bars.iter().zip(cells.chunks_exact_mut(7)) {
            let flags = if bar.memory64 {
                0x0300_0000
            } else {
                0x0200_0000
            } | if bar.prefetchable { 0x4000_0000 } else { 0 };
            cells.copy_from_slice(&[
                flags,
                (bar.bus_address >> 32) as u32,
                bar.bus_address as u32,
                (bar.window.base >> 32) as u32,
                bar.window.base as u32,
                (bar.window.size >> 32) as u32,
                bar.window.size as u32,
            ]);
        }
        builder.property_cells("ranges", &cells[..self.bars.len() * 7])?;
        let mut cells = [0; super::MAX_DMA_RANGES * 7];
        for (range, cells) in io.dma_ranges.iter().zip(cells.chunks_exact_mut(7)) {
            let bus = range
                .dma_base
                .checked_add(self.dma_bus_offset)
                .ok_or(Error::AddressOverflow)?;
            cells.copy_from_slice(&[
                0x4300_0000,
                (bus >> 32) as u32,
                bus as u32,
                (range.cpu_base >> 32) as u32,
                range.cpu_base as u32,
                (range.size >> 32) as u32,
                range.size as u32,
            ]);
        }
        builder.property_cells("dma-ranges", &cells[..io.dma_ranges.len() * 7])?;
        firmware::append(builder, self.nodes)?;
        builder.end_node()
    }
}
