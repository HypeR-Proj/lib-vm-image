// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Firmware description of a userspace-owned PCI ECAM bus, without host DMA.

use super::{Aarch64LinuxBoot, Builder, Error, IoDevices, MmioWindow, hex_node_name};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPci<'a> {
    pub ecam: MmioWindow,
    pub memory: MmioWindow,
    /// (device number, full GIC INTID) for INTA of each single-function endpoint.
    pub interrupts: &'a [(u8, u32)],
}

impl VirtualPci<'_> {
    pub(super) fn validate(
        self,
        io: IoDevices<'_>,
        boot: Aarch64LinuxBoot<'_>,
    ) -> Result<(), Error> {
        // Virtual DMA always uses the guest's ordinary RAM and its existing
        // backend memory grant. Never inherit host assignment DMA translations.
        if io.pci.is_some()
            || io.virtio.is_some()
            || io.network.is_some()
            || io.sdhci.is_some()
            || !io.clients.is_empty()
            || !io.dma_ranges.is_empty()
            || io.shared_memory.is_some()
            || io.mailbox.is_some()
            || io.notification.is_some()
            || self.ecam.size != 1 << 20
            || !self.ecam.base.is_multiple_of(1 << 20)
            || self.interrupts.is_empty()
            || self.interrupts.len() > 8
        {
            return Err(Error::InvalidInput);
        }
        for window in [self.ecam, self.memory] {
            let end = window
                .base
                .checked_add(window.size)
                .ok_or(Error::AddressOverflow)?;
            if window.size == 0
                || !(window.base | window.size).is_multiple_of(4096)
                || window.base < 0x0a00_0000
                || end > 0x0b00_0000
                || super::overlaps(
                    window.base,
                    end,
                    boot.memory_base,
                    super::end(boot.memory_base, boot.memory_size)?,
                )
            {
                return Err(Error::InvalidInput);
            }
        }
        if super::overlaps(
            self.ecam.base,
            self.ecam.base + self.ecam.size,
            self.memory.base,
            self.memory.base + self.memory.size,
        ) {
            return Err(Error::InvalidInput);
        }
        for (index, &(slot, irq)) in self.interrupts.iter().enumerate() {
            if slot >= 32
                || !super::device_irq(irq)
                || self.interrupts[..index]
                    .iter()
                    .any(|&(other, line)| slot == other || irq == line)
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }

    pub(super) fn append(self, builder: &mut Builder<'_>) -> Result<(), Error> {
        let mut name = [0; 64];
        builder.begin_node(hex_node_name("pcie@", self.ecam.base, &mut name)?)?;
        builder.property_string("compatible", "pci-host-ecam-generic")?;
        builder.property_string("device_type", "pci")?;
        builder.property_u32("#address-cells", 3)?;
        builder.property_u32("#size-cells", 2)?;
        builder.property_u32("#interrupt-cells", 1)?;
        builder.property_u64_pair("reg", self.ecam.base, self.ecam.size)?;
        builder.property_cells("bus-range", &[0, 0])?;
        builder.property_empty("dma-coherent")?;
        builder.property_cells(
            "ranges",
            &[
                0x0200_0000,
                0,
                self.memory.base as u32,
                0,
                self.memory.base as u32,
                0,
                self.memory.size as u32,
            ],
        )?;
        builder.property_cells("interrupt-map-mask", &[0xf800, 0, 0, 7])?;
        let mut cells = [0; 8 * 8];
        for (&(slot, irq), entry) in self.interrupts.iter().zip(cells.chunks_exact_mut(8)) {
            // GIC has #address-cells=0 and three interrupt cells.
            entry.copy_from_slice(&[
                u32::from(slot) << 11,
                0,
                0,
                1,
                crate::guest_fdt::GIC_PHANDLE,
                0,
                irq - 32,
                4,
            ]);
        }
        builder.property_cells("interrupt-map", &cells[..self.interrupts.len() * 8])?;
        builder.end_node()
    }
}
