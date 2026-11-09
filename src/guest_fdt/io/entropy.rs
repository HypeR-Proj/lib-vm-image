// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! The rng200 assignment occupies one aperture but exposes only its register bank.
use super::{Aarch64LinuxBoot, Error, IoDevices, overlaps};
pub(super) fn validate(io: IoDevices<'_>, boot: Aarch64LinuxBoot<'_>) -> Result<(), Error> {
    let Some(rng) = io.entropy else {
        return Ok(());
    };
    if rng.base != 0x0b02_0000 || rng.size != 0x28 {
        return Err(Error::InvalidInput);
    }
    let check = |base: u64, size: u64| -> Result<(), Error> {
        let end = base.checked_add(size).ok_or(Error::AddressOverflow)?;
        if overlaps(rng.base, rng.base + 65536, base, end) {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    };
    let irq = |number: u32| {
        if number == 122 {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    };
    check(boot.memory_base, boot.memory_size)?;
    if let Some((base, end)) = boot.initramfs {
        check(base, end.checked_sub(base).ok_or(Error::InvalidInput)?)?;
    }
    if let Some(memory) = io.shared_memory {
        check(memory.base, memory.size)?;
    }
    for device in [io.storage_node(), io.network, io.mailbox, io.notification]
        .into_iter()
        .flatten()
    {
        check(
            device.base,
            if !io.dma_ranges.is_empty() {
                65536
            } else {
                4096
            },
        )?;
        irq(device.irq)?;
    }
    if let Some(sdhci) = io.sdhci {
        for window in [
            sdhci.config,
            sdhci.main_pinctrl,
            sdhci.aon_pinctrl,
            sdhci.aon_gpio,
        ] {
            check(window.base, window.size)?;
        }
    }
    for client in io.clients {
        check(client.shared_memory.base, client.shared_memory.size)?;
        for device in [
            Some(client.mailbox),
            client.notification,
            client.network_notification,
        ]
        .into_iter()
        .flatten()
        {
            check(device.base, 4096)?;
            irq(device.irq)?;
        }
    }
    if let Some(pci) = io.hotplug_pci {
        check(pci.ecam.base, pci.ecam.size)?;
        check(pci.memory.base, pci.memory.size)?;
        irq(pci.hotplug_irq)?;
        irq(pci.endpoint_irq)?;
    }
    if io.virtual_pci.is_some() {
        return Err(Error::InvalidInput);
    }
    if let Some(pci) = io.pci {
        check(pci.aperture.base, pci.aperture.size)?;
        if pci.interrupt_base <= 122
            && pci
                .interrupt_base
                .checked_add(pci.interrupt_count)
                .is_none_or(|end| end > 122)
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}
