// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! A virtual `PCIe` root port alongside, but outside, assigned-device DMA buses.

use super::{Aarch64LinuxBoot, Builder, Error, IoDevices, MmioWindow, hex_node_name};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotplugPci {
    pub ecam: MmioWindow,
    pub memory: MmioWindow,
    pub hotplug_irq: u32,
    /// The downstream device uses INTB; slot zero leaves its pin unswizzled.
    pub endpoint_irq: u32,
}
impl HotplugPci {
    pub(super) fn validate(
        self,
        io: IoDevices<'_>,
        boot: Aarch64LinuxBoot<'_>,
    ) -> Result<(), Error> {
        // The flat endpoint transport and this root port each own one virtual
        // host bridge. A deployment selects one topology, not both aliases.
        if io.virtual_pci.is_some() {
            return Err(Error::InvalidInput);
        }
        if self.ecam.size != 2 << 20
            || !self.ecam.base.is_multiple_of(1 << 20)
            || self.memory.size < 1 << 20
            || !(self.memory.base | self.memory.size).is_multiple_of(1 << 20)
            || !super::device_irq(self.hotplug_irq)
            || !super::device_irq(self.endpoint_irq)
            || self.hotplug_irq == self.endpoint_irq
        {
            return Err(Error::InvalidInput);
        }
        let windows = [self.ecam, self.memory];
        let check_memory = |base: u64, size: u64| -> Result<(), Error> {
            let end = base.checked_add(size).ok_or(Error::AddressOverflow)?;
            for window in windows {
                let limit = window
                    .base
                    .checked_add(window.size)
                    .ok_or(Error::AddressOverflow)?;
                if super::overlaps(base, end, window.base, limit) {
                    return Err(Error::InvalidInput);
                }
            }
            Ok(())
        };
        let check_irq = |irq: u32| -> Result<(), Error> {
            if [self.hotplug_irq, self.endpoint_irq].contains(&irq) {
                Err(Error::InvalidInput)
            } else {
                Ok(())
            }
        };
        for window in windows {
            if window.base < 0x0a00_0000
                || window
                    .base
                    .checked_add(window.size)
                    .is_none_or(|end| end > 0x0b00_0000)
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
        check_memory(boot.memory_base, boot.memory_size)?;
        if let Some(shared) = io.shared_memory {
            check_memory(shared.base, shared.size)?;
        }
        for device in [io.storage_node(), io.network, io.mailbox, io.notification]
            .into_iter()
            .flatten()
        {
            check_memory(device.base, 4096)?;
            check_irq(device.irq)?;
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
                check_memory(device.base, 4096)?;
                check_irq(device.irq)?;
            }
        }
        if let Some(pci) = io.pci {
            check_memory(pci.aperture.base, pci.aperture.size)?;
            let end = pci
                .interrupt_base
                .checked_add(pci.interrupt_count)
                .ok_or(Error::AddressOverflow)?;
            if (pci.interrupt_base..end).contains(&self.hotplug_irq)
                || (pci.interrupt_base..end).contains(&self.endpoint_irq)
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
        builder.property_u32("linux,pci-domain", 1)?;
        builder.property_u32("#address-cells", 3)?;
        builder.property_u32("#size-cells", 2)?;
        builder.property_u32("#interrupt-cells", 1)?;
        builder.property_u64_pair("reg", self.ecam.base, self.ecam.size)?;
        builder.property_cells("bus-range", &[0, 1])?;
        builder.property_empty("dma-coherent")?;
        // Identity DMA is confined to the VM's own memory by its device service.
        // Assigned SDHCI/RP1 translations belong to their distinct sibling bus.
        builder.property_empty("dma-ranges")?;
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
        builder.property_cells(
            "interrupt-map",
            &[
                0,
                0,
                0,
                1,
                super::super::GIC_PHANDLE,
                0,
                self.hotplug_irq - 32,
                4,
                0,
                0,
                0,
                2,
                super::super::GIC_PHANDLE,
                0,
                self.endpoint_irq - 32,
                4,
            ],
        )?;
        builder.end_node()
    }
}
