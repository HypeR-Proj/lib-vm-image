// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

extern crate std;
#[path = "pci_fdt.rs"]
mod pci;
use super::{DmaRange, IoDevices, MmioDevice, SharedMemory};
use crate::guest_fdt::{Aarch64LinuxBoot, Error, build_aarch64_linux_with_io};
use std::{collections::BTreeMap, string::String, vec::Vec};

const MIB: u64 = 1024 * 1024;
const DMA: [DmaRange; 2] = [
    DmaRange {
        dma_base: 0x1_8000_0000,
        cpu_base: 0x4000_0000,
        size: 64 * MIB,
    },
    DmaRange {
        dma_base: 0x2_9000_0000,
        cpu_base: 0x4400_0000,
        size: 64 * MIB,
    },
];
fn boot() -> Aarch64LinuxBoot<'static> {
    Aarch64LinuxBoot {
        memory_base: 0x4000_0000,
        memory_size: 64 * MIB,
        vcpu_count: 2,
        gic_version: 3,
        initramfs: Some((0x4100_0000, 0x4120_0000)),
        boot_arguments: "console=ttyAMA0 hyper.role=io",
    }
}
fn devices() -> IoDevices<'static> {
    IoDevices {
        clients: &[],
        sdhci: None,
        pci: None,
        virtual_pci: None,
        network: None,
        virtio: Some(MmioDevice {
            base: 0x0b00_0000,
            size: 0x200,
            irq: 40,
        }),
        dma_ranges: &DMA,
        shared_memory: Some(SharedMemory {
            base: 0x4400_0000,
            size: 64 * MIB,
            guest_base: 0x4000_0000,
        }),
        mailbox: Some(MmioDevice {
            base: 0x0a00_0000,
            size: 4096,
            irq: 41,
        }),
        notification: Some(MmioDevice {
            base: 0x0a00_1000,
            size: 4096,
            irq: 42,
        }),
    }
}
fn build(devices: IoDevices<'_>) -> Result<Vec<u8>, Error> {
    let mut structure = [0; 8192];
    let mut strings = [0; 2048];
    let mut output = [0; 12288];
    let length =
        build_aarch64_linux_with_io(boot(), devices, &mut structure, &mut strings, &mut output)?;
    Ok(output[..length].to_vec())
}
fn word(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("word extent")?
            .try_into()
            .map_err(|_| "word")?,
    ))
}
fn text(bytes: &[u8], offset: usize) -> Result<(&str, usize), &'static str> {
    let tail = bytes.get(offset..).ok_or("string extent")?;
    let end = tail
        .iter()
        .position(|value| *value == 0)
        .ok_or("string terminator")?;
    Ok((
        core::str::from_utf8(&tail[..end]).map_err(|_| "string encoding")?,
        end + 1,
    ))
}
// Parse paths and cell bytes independently of the production encoder.
fn properties(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, &'static str> {
    if word(bytes, 0)? != 0xd00d_feed || word(bytes, 4)? as usize != bytes.len() {
        return Err("header");
    }
    let mut at = word(bytes, 8)? as usize;
    let end = at + word(bytes, 36)? as usize;
    let strings = word(bytes, 12)? as usize;
    let mut path = Vec::<String>::new();
    let mut result = BTreeMap::new();
    while at < end {
        let token = word(bytes, at)?;
        at += 4;
        match token {
            1 => {
                let (name, length) = text(bytes, at)?;
                path.push(String::from(name));
                at = (at + length + 3) & !3;
            }
            2 => {
                path.pop().ok_or("unbalanced node")?;
            }
            3 => {
                let length = word(bytes, at)? as usize;
                let name = word(bytes, at + 4)? as usize;
                at += 8;
                let (name, _) = text(bytes, strings + name)?;
                let key = std::format!("{}/{name}", path.join("/"));
                if result
                    .insert(
                        key,
                        bytes
                            .get(at..at + length)
                            .ok_or("property extent")?
                            .to_vec(),
                    )
                    .is_some()
                {
                    return Err("duplicate");
                }
                at = (at + length + 3) & !3;
            }
            9 if path.is_empty() && at == end => return Ok(result),
            _ => return Err("token"),
        }
    }
    Err("missing end")
}

#[test]
fn reference_uart_advertises_the_sbsa_interface() -> Result<(), &'static str> {
    for devices in [IoDevices::empty(), devices()] {
        let values = properties(&build(devices).map_err(|_| "build")?)?;
        let value = |path| {
            values
                .get(path)
                .map(Vec::as_slice)
                .ok_or("missing property")
        };
        assert_eq!(value("/uart@9000000/compatible")?, b"arm,sbsa-uart\0");
        assert_eq!(
            value("/uart@9000000/current-speed")?,
            115_200u32.to_be_bytes()
        );
        assert_eq!(
            value("/uart@9000000/reg")?,
            [0x0900_0000u64.to_be_bytes(), 0x1000u64.to_be_bytes()].concat()
        );
        assert_eq!(
            value("/uart@9000000/interrupts")?,
            [0u32.to_be_bytes(), 1u32.to_be_bytes(), 4u32.to_be_bytes()].concat()
        );
        assert_eq!(value("/aliases/serial0")?, b"/uart@9000000\0");
        assert_eq!(value("/chosen/stdout-path")?, b"/uart@9000000\0");
        assert!(!values.contains_key("/uart@9000000/clocks"));
        assert!(!values.contains_key("/uart@9000000/clock-names"));
        assert!(!values.contains_key("/pl011@9000000/compatible"));
    }
    Ok(())
}

#[test]
fn physical_tree_maps_host_dma_addresses_and_retains_imported_struct_pages()
-> Result<(), &'static str> {
    let values = properties(&build(devices()).map_err(|_| "build")?)?;
    let value = |path| {
        values
            .get(path)
            .map(Vec::as_slice)
            .ok_or("missing property")
    };
    assert_eq!(
        value("/memory@40000000/reg")?,
        [0x4000_0000u64.to_be_bytes(), (64 * MIB).to_be_bytes()].concat()
    );
    assert_eq!(
        value("/memory@44000000/reg")?,
        value("/reserved-memory/guest-memory@44000000/reg")?
    );
    assert!(!values.contains_key("/reserved-memory/guest-memory@44000000/no-map"));
    assert!(!values.contains_key("/reserved-memory/guest-memory@44000000/reusable"));
    assert_eq!(
        value("/hyper-guest-memory/memory-region")?,
        value("/reserved-memory/guest-memory@44000000/phandle")?
    );
    assert_eq!(
        value("/hyper-guest-memory/hyper,guest-base")?,
        0x4000_0000u64.to_be_bytes()
    );
    let expected: Vec<_> = DMA
        .iter()
        .flat_map(|range| [range.dma_base, range.cpu_base, range.size])
        .flat_map(u64::to_be_bytes)
        .collect();
    assert_eq!(value("/io-bus/dma-ranges")?, expected);
    assert!(values.contains_key("/io-bus/dma-coherent"));
    assert_eq!(
        value("/io-bus/virtio_mmio@b000000/interrupts")?,
        [0u32.to_be_bytes(), 8u32.to_be_bytes(), 4u32.to_be_bytes()].concat()
    );
    assert_eq!(
        value("/guest-mailbox@a000000/compatible")?,
        b"hyper,guest-mailbox-v1\0"
    );
    assert_eq!(
        value("/guest-notification@a001000/compatible")?,
        b"hyper,guest-notification-v1\0"
    );
    Ok(())
}

#[test]
fn frontend_tree_uses_standard_virtio_without_physical_dma_authority() -> Result<(), &'static str> {
    let devices = IoDevices {
        clients: &[],
        virtio: Some(MmioDevice {
            base: 0x0a00_0000,
            size: 4096,
            irq: 40,
        }),
        ..IoDevices::empty()
    };
    let values = properties(&build(devices).map_err(|_| "build")?)?;
    assert_eq!(
        values
            .get("/virtio_mmio@a000000/compatible")
            .ok_or("virtio")?,
        b"virtio,mmio\0"
    );
    assert!(!values.contains_key("/io-bus/dma-ranges"));
    assert!(!values.contains_key("/reserved-memory/#address-cells"));
    Ok(())
}

#[test]
fn rejects_dma_holes_aliasing_overflow_and_irq_collisions() {
    let mut invalid = devices();
    invalid.dma_ranges = &DMA[..1];
    assert_eq!(build(invalid), Err(Error::InvalidInput));
    let mut overlap = DMA;
    overlap[1].dma_base = overlap[0].dma_base;
    invalid.dma_ranges = &overlap;
    assert_eq!(build(invalid), Err(Error::InvalidInput));
    let mut overlap = DMA;
    overlap[1].cpu_base = overlap[0].cpu_base;
    invalid.dma_ranges = &overlap;
    assert_eq!(build(invalid), Err(Error::InvalidInput));
    let mut overlap = DMA;
    overlap[1].dma_base = !4095u64;
    invalid.dma_ranges = &overlap;
    assert_eq!(build(invalid), Err(Error::AddressOverflow));
    invalid = devices();
    invalid.notification = invalid.mailbox;
    assert_eq!(build(invalid), Err(Error::InvalidInput));
    invalid = devices();
    invalid.mailbox = Some(MmioDevice {
        base: 0x0a00_0000,
        size: 4096,
        irq: 33,
    });
    assert_eq!(build(invalid), Err(Error::InvalidInput));
}

#[test]
fn reserved_alias_cannot_overlap_linux_allocatable_ram() {
    let mut invalid = devices();
    invalid.shared_memory = Some(SharedMemory {
        base: 0x4200_0000,
        size: 64 * MIB,
        guest_base: 0x4000_0000,
    });
    assert_eq!(build(invalid), Err(Error::InvalidInput));
}

fn client(id: u32, memory: u64, dynamic: bool) -> super::IoClient {
    super::IoClient {
        id,
        shared_memory: SharedMemory {
            base: memory,
            size: 64 * MIB,
            guest_base: 0x4000_0000,
        },
        mailbox: MmioDevice {
            base: 0x0a00_0000 + u64::from(id) * 8192,
            size: 4096,
            irq: 41 + id * 2,
        },
        notification: Some(MmioDevice {
            base: 0x0a00_1000 + u64::from(id) * 8192,
            size: 4096,
            irq: 42 + id * 2,
        }),
        network_notification: None,
        dynamic,
    }
}

#[test]
fn owner_control_channel_does_not_require_a_data_notification() -> Result<(), &'static str> {
    let mut owner = client(0, 0x4400_0000, false);
    owner.notification = None;
    let tree = build(IoDevices {
        clients: &[owner],
        ..IoDevices::empty()
    })
    .map_err(|_| "control-only owner")?;
    let values = properties(&tree)?;
    assert_eq!(
        values
            .get("/guest-mailbox@a000000/hyper,client-id")
            .ok_or("owner mailbox id")?,
        &0_u32.to_be_bytes()
    );
    assert!(values.contains_key("/hyper-guest-memory@0/memory-region"));
    assert!(
        values
            .keys()
            .all(|key| !key.starts_with("/guest-notification@"))
    );
    owner.id = 1;
    assert_eq!(
        build(IoDevices {
            clients: &[owner],
            ..IoDevices::empty()
        }),
        Err(Error::InvalidInput)
    );
    Ok(())
}

#[test]
fn clients_have_distinct_phandles_and_context_ids() -> Result<(), &'static str> {
    let clients = [client(0, 0x4400_0000, false), client(3, 0x4800_0000, false)];
    let tree = build(IoDevices {
        clients: &clients,
        ..IoDevices::empty()
    })
    .map_err(|_| "build")?;
    let values = properties(&tree)?;
    assert_eq!(
        values
            .get("/hyper-guest-memory@0/memory-region")
            .ok_or("first phandle")?,
        values
            .get("/reserved-memory/guest-memory@44000000/phandle")
            .ok_or("first memory phandle")?
    );
    assert_eq!(
        values
            .get("/hyper-guest-memory@3/memory-region")
            .ok_or("second phandle")?,
        values
            .get("/reserved-memory/guest-memory@48000000/phandle")
            .ok_or("second memory phandle")?
    );
    assert_eq!(
        values
            .get("/guest-mailbox@a006000/hyper,client-id")
            .ok_or("mailbox id")?,
        &3u32.to_be_bytes()
    );
    assert_eq!(
        values
            .get("/guest-notification@a007000/hyper,client-id")
            .ok_or("notification id")?,
        &3u32.to_be_bytes()
    );
    Ok(())
}

#[test]
fn dynamic_windows_do_not_claim_ram_or_preallocated_pages() -> Result<(), &'static str> {
    let clients = [
        client(0, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true),
        client(1, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true),
    ];
    let dma = [
        DMA[0],
        DmaRange {
            dma_base: 0x8000_0000,
            cpu_base: super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000,
            size: 64 * MIB,
        },
    ];
    let devices = IoDevices {
        clients: &clients,
        virtio: devices().virtio,
        dma_ranges: &dma,
        ..IoDevices::empty()
    };
    let values = properties(&build(devices).map_err(|_| "build")?)?;
    assert!(values.contains_key("/hyper-guest-memory-0@1080000000/hyper,dynamic-memory"));
    assert!(values.contains_key("/hyper-guest-memory-1@1080000000/hyper,dynamic-memory"));
    assert!(!values.contains_key("/memory@1080000000/reg"));
    assert!(!values.contains_key("/reserved-memory/#address-cells"));
    assert!(!values.contains_key("/hyper-guest-memory-0@1080000000/memory-region"));
    let mut linux_names = std::collections::BTreeSet::new();
    for id in [0u32, 1] {
        let node = std::format!("/hyper-guest-memory-{id}@1080000000");
        assert_eq!(
            values.get(&(node.clone() + "/hyper,client-id")),
            Some(&id.to_be_bytes().to_vec())
        );
        assert_eq!(
            values.get(&(node.clone() + "/compatible")),
            Some(&b"hyper,guest-memory-v1\0".to_vec())
        );
        let reg = values.get(&(node.clone() + "/reg")).ok_or("dynamic reg")?;
        let base = u64::from_be_bytes(reg[..8].try_into().map_err(|_| "base")?);
        let basename = node
            .trim_start_matches('/')
            .split('@')
            .next()
            .ok_or("basename")?;
        // of_device_make_bus_id combines translated address and basename;
        // distinct unit addresses alone would still collide in Linux sysfs.
        assert!(linux_names.insert(std::format!("{base:x}.{basename}")));
    }
    Ok(())
}

#[test]
fn rejects_ambiguous_or_fabricated_dynamic_dma_translation() {
    let clients = [client(0, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true)];
    let mut dma = [
        DMA[0],
        DmaRange {
            dma_base: 0x9000_0000,
            cpu_base: super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000,
            size: 64 * MIB,
        },
    ];
    let check = |ranges: &[DmaRange]| {
        build(IoDevices {
            clients: &clients,
            virtio: devices().virtio,
            dma_ranges: ranges,
            ..IoDevices::empty()
        })
    };
    assert_eq!(check(&dma), Err(Error::InvalidInput));
    dma[1].dma_base = dma[1].cpu_base - super::DYNAMIC_ALIAS_OFFSET;
    dma[0].dma_base = dma[1].dma_base;
    assert_eq!(check(&dma), Err(Error::InvalidInput));
    assert_eq!(check(&dma[1..]), Err(Error::InvalidInput));
}

#[test]
fn rejects_duplicate_client_or_cross_context_irq_and_static_alias() {
    let mut clients = [client(0, 0x4400_0000, false), client(1, 0x4800_0000, false)];
    if let Some(notification) = clients[1].notification.as_mut() {
        notification.irq = clients[0].mailbox.irq;
    }
    assert_eq!(
        build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        }),
        Err(Error::InvalidInput)
    );
    clients[1] = client(0, 0x4800_0000, false);
    assert_eq!(
        build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        }),
        Err(Error::InvalidInput)
    );
    clients[1] = client(1, 0x4400_0000, false);
    assert_eq!(
        build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        }),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        build(IoDevices {
            clients: &clients[..1],
            mailbox: Some(clients[0].mailbox),
            ..IoDevices::empty()
        }),
        Err(Error::InvalidInput)
    );
}

#[test]
fn all_native_client_slots_fit_the_device_table() {
    let clients: Vec<_> = (0..hyper_abi::HYPER_NATIVE_IO_MAX_CLIENTS as u32)
        .map(|id| client(id, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true))
        .collect();
    assert!(
        build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        })
        .is_ok()
    );
}

fn network_notification(id: u32) -> MmioDevice {
    MmioDevice {
        base: 0x0a20_0000 + u64::from(id) * 0x10000,
        size: 4096,
        irq: 64 + id,
    }
}

#[test]
fn physical_network_and_storage_share_one_explicit_dma_bus() -> Result<(), &'static str> {
    let mut io = devices();
    io.network = Some(MmioDevice {
        base: 0x0b01_0000,
        size: 512,
        irq: 59,
    });
    let values = properties(&build(io).map_err(|_| "two physical devices")?)?;
    for base in [0x0b00_0000u64, 0x0b01_0000] {
        let node = std::format!("/io-bus/virtio_mmio@{base:x}");
        assert_eq!(
            values.get(&(node.clone() + "/compatible")),
            Some(&b"virtio,mmio\0".to_vec())
        );
        assert_eq!(
            values.get(&(node + "/reg")),
            Some(&[base.to_be_bytes(), 512u64.to_be_bytes(),].concat())
        );
        assert!(!values.contains_key(&std::format!("/virtio_mmio@{base:x}/compatible")));
    }
    assert_eq!(
        values
            .keys()
            .filter(|key| key.ends_with("/dma-ranges"))
            .count(),
        1
    );
    assert_eq!(
        values.get("/io-bus/dma-ranges"),
        Some(
            &DMA.iter()
                .flat_map(|range| [range.dma_base, range.cpu_base, range.size])
                .flat_map(u64::to_be_bytes)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        values.get("/io-bus/virtio_mmio@b010000/interrupts"),
        Some(
            &[0u32, 27, 4]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>()
        )
    );
    Ok(())
}

#[test]
fn guest_network_and_storage_have_independent_virtio_nodes_without_dma_authority()
-> Result<(), &'static str> {
    let network = MmioDevice {
        base: 0x0a00_1000,
        size: 4096,
        irq: 49,
    };
    for storage in [
        None,
        Some(MmioDevice {
            base: 0x0a00_0000,
            size: 4096,
            irq: 48,
        }),
    ] {
        let values = properties(
            &build(IoDevices {
                virtio: storage,
                network: Some(network),
                ..IoDevices::empty()
            })
            .map_err(|_| "guest frontend tree")?,
        )?;
        assert_eq!(
            values.contains_key("/virtio_mmio@a000000/compatible"),
            storage.is_some()
        );
        assert_eq!(
            values.get("/virtio_mmio@a001000/compatible"),
            Some(&b"virtio,mmio\0".to_vec())
        );
        assert!(
            !values
                .keys()
                .any(|key| key.starts_with("/io-bus/") || key.ends_with("/dma-ranges"))
        );
        assert!(
            !values
                .keys()
                .any(|key| key.starts_with("/guest-notification@"))
        );
    }
    Ok(())
}

#[test]
fn network_only_client_uses_one_memory_identity_without_a_storage_notification()
-> Result<(), &'static str> {
    let mut guest = client(1, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true);
    guest.notification = None;
    guest.network_notification = Some(network_notification(1));
    let clients = [client(0, 0x4400_0000, false), guest];
    let values = properties(
        &build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        })
        .map_err(|_| "network-only client")?,
    )?;
    assert_eq!(
        values.get("/guest-notification@a210000/hyper,device-kind"),
        Some(&b"network\0".to_vec())
    );
    assert_eq!(
        values.get("/guest-notification@a210000/hyper,client-id"),
        Some(&1u32.to_be_bytes().to_vec())
    );
    assert!(!values.contains_key("/guest-notification@a003000/compatible"));
    assert!(!values.contains_key("/guest-notification@a200000/compatible"));
    assert!(!values.contains_key("/guest-notification@a001000/hyper,device-kind"));
    assert_eq!(
        values
            .keys()
            .filter(|key| key.ends_with("/hyper,dynamic-memory"))
            .count(),
        1
    );
    assert_eq!(
        values
            .keys()
            .filter(|key| key.ends_with("/hyper,device-kind"))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn all_eight_network_clients_fit_high_interrupts_without_consuming_native_reservation()
-> Result<(), &'static str> {
    let clients: Vec<_> = (0..hyper_abi::HYPER_NATIVE_IO_MAX_CLIENTS as u32)
        .map(|id| {
            let mut client = client(id, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true);
            if id != 0 {
                client.network_notification = Some(network_notification(id));
            }
            client
        })
        .collect();
    let values = properties(
        &build(IoDevices {
            clients: &clients,
            ..IoDevices::empty()
        })
        .map_err(|_| "full client table")?,
    )?;
    for id in 1..=8u32 {
        let path = std::format!("/guest-notification@{:x}", network_notification(id).base);
        assert_eq!(
            values.get(&(path.clone() + "/hyper,device-kind")),
            Some(&b"network\0".to_vec())
        );
        assert_eq!(
            values.get(&(path + "/interrupts")),
            Some(
                &[0u32, 32 + id, 4]
                    .into_iter()
                    .flat_map(u32::to_be_bytes)
                    .collect::<Vec<_>>()
            )
        );
    }
    assert_eq!(
        values
            .keys()
            .filter(|key| key.ends_with("/hyper,device-kind"))
            .count(),
        8
    );
    assert!(!values.contains_key("/guest-notification@a200000/compatible"));
    assert_eq!(
        values
            .keys()
            .filter(|key| key.starts_with("/guest-mailbox@") && key.ends_with("/compatible"))
            .count(),
        9
    );
    assert_eq!(
        values
            .keys()
            .filter(|key| key.starts_with("/guest-notification@") && key.ends_with("/compatible"))
            .count(),
        17
    );
    Ok(())
}

#[test]
fn network_devices_reject_cross_kind_irq_and_mmio_collisions() {
    for network in [
        MmioDevice {
            base: 0x0b00_0000,
            size: 512,
            irq: 59,
        },
        MmioDevice {
            base: 0x0b01_0000,
            size: 512,
            irq: 40,
        },
        MmioDevice {
            base: 0x0b01_0000,
            size: 512,
            irq: hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_INTERRUPT_COUNT as u32,
        },
    ] {
        assert_eq!(
            build(IoDevices {
                network: Some(network),
                ..devices()
            }),
            Err(Error::InvalidInput)
        );
    }
    let mut clients = [client(1, super::DYNAMIC_ALIAS_OFFSET + 0x8000_0000, true)];
    for network in [
        MmioDevice {
            irq: clients[0].mailbox.irq,
            ..network_notification(1)
        },
        MmioDevice {
            base: clients[0].mailbox.base,
            ..network_notification(1)
        },
        MmioDevice {
            irq: hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_INTERRUPT_COUNT as u32,
            ..network_notification(1)
        },
    ] {
        clients[0].network_notification = Some(network);
        assert_eq!(
            build(IoDevices {
                clients: &clients,
                ..IoDevices::empty()
            }),
            Err(Error::InvalidInput)
        );
    }
}

fn sdhci(revision: super::SdhciRevision) -> super::SdhciDevice {
    use super::{MmioWindow, SdhciDevice, SdhciRevision};
    let c0 = revision == SdhciRevision::C0;
    SdhciDevice {
        host: MmioDevice {
            base: 0x0b00_0000,
            size: 0x260,
            irq: 40,
        },
        config: MmioWindow {
            base: 0x0b00_0400,
            size: 0x200,
        },
        main_pinctrl: MmioWindow {
            base: 0x0b00_1100,
            size: if c0 { 0x30 } else { 0x20 },
        },
        aon_pinctrl: MmioWindow {
            base: 0x0b00_2700,
            size: if c0 { 0x20 } else { 0x1c },
        },
        aon_gpio: MmioWindow {
            base: 0x0b00_3c00,
            size: 0x40,
        },
        revision,
        clock_hz: 200_000_000,
        gpio_widths: [if c0 { 17 } else { 15 }, 6],
    }
}

#[test]
fn sdhci_preserves_admitted_windows_and_upstream_dependency_cells() -> Result<(), &'static str> {
    for revision in [super::SdhciRevision::C0, super::SdhciRevision::D0] {
        let sd = sdhci(revision);
        let tree = build(IoDevices {
            virtio: None,
            sdhci: Some(sd),
            ..devices()
        })
        .map_err(|_| "SD tree")?;
        let props = properties(&tree)?;
        let get = |key| {
            props
                .get(key)
                .map(Vec::as_slice)
                .ok_or("missing SD property")
        };
        assert!(!props.keys().any(|key| key.ends_with("/dma-coherent")));
        assert_eq!(
            get("/io-bus/mmc@b000000/reg")?,
            [sd.host.base, sd.host.size, sd.config.base, sd.config.size]
                .into_iter()
                .flat_map(u64::to_be_bytes)
                .collect::<Vec<_>>()
        );
        for (path, window) in [
            ("/io-bus/pinctrl@b001100/reg", sd.main_pinctrl),
            ("/io-bus/pinctrl@b002700/reg", sd.aon_pinctrl),
            ("/io-bus/gpio@b003c00/reg", sd.aon_gpio),
        ] {
            assert_eq!(
                get(path)?,
                [window.base.to_be_bytes(), window.size.to_be_bytes()].concat()
            );
        }
        assert_eq!(get("/io-bus/#address-cells")?, 2u32.to_be_bytes());
        assert_eq!(get("/io-bus/#size-cells")?, 2u32.to_be_bytes());
        assert_eq!(get("/io-bus/sd-clock/#clock-cells")?, 0u32.to_be_bytes());
        assert_eq!(
            get("/io-bus/mmc@b000000/clocks")?,
            get("/io-bus/sd-clock/phandle")?
        );
        assert_eq!(
            get("/io-bus/sd-clock/clock-frequency")?,
            200_000_000u32.to_be_bytes()
        );
        assert_eq!(
            get("/io-bus/mmc@b000000/interrupts")?,
            [0u32, 8, 4]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            get("/io-bus/mmc@b000000/pinctrl-0")?,
            [
                get("/io-bus/pinctrl@b001100/emmc-sd-default-state/phandle")?,
                get("/io-bus/pinctrl@b002700/emmc-aon-cd-default-state/phandle")?
            ]
            .concat()
        );
        assert_eq!(
            get("/io-bus/mmc@b000000/vqmmc-supply")?,
            get("/io-bus/sd-io-voltage/phandle")?
        );
        assert_eq!(
            get("/io-bus/mmc@b000000/vmmc-supply")?,
            get("/io-bus/sd-card-power/phandle")?
        );
        assert_eq!(get("/io-bus/gpio@b003c00/#gpio-cells")?, 2u32.to_be_bytes());
        for (path, pin, flags) in [
            ("/io-bus/sd-io-voltage/gpios", 3u32, 0u32),
            ("/io-bus/sd-card-power/gpios", 4, 0),
            ("/io-bus/mmc@b000000/cd-gpios", 5, 1),
        ] {
            assert_eq!(
                get(path)?,
                [
                    get("/io-bus/gpio@b003c00/phandle")?,
                    &pin.to_be_bytes(),
                    &flags.to_be_bytes()
                ]
                .concat()
            );
        }
        assert!(!props.contains_key("/io-bus/gpio@b003c00/interrupts"));
        assert!(!props.contains_key("/io-bus/gpio@b003c00/interrupt-controller"));
        assert_eq!(
            get("/io-bus/sd-io-voltage/states")?,
            [1_800_000u32, 1, 3_300_000, 0]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>()
        );
        let revision = if revision == super::SdhciRevision::C0 {
            b"brcm,bcm2712c0-pinctrl\0"
        } else {
            b"brcm,bcm2712d0-pinctrl\0"
        };
        assert_eq!(get("/io-bus/pinctrl@b001100/compatible")?, revision);
    }
    Ok(())
}

#[test]
fn sdhci_rejects_missing_dma_overlap_and_inconsistent_silicon_facts() {
    let device = sdhci(super::SdhciRevision::C0);
    let mut io = IoDevices {
        sdhci: Some(device),
        ..devices()
    };
    assert_eq!(build(io), Err(Error::InvalidInput)); // two physical devices
    io.virtio = None;
    io.dma_ranges = &[];
    assert_eq!(build(io), Err(Error::InvalidInput));
    io.dma_ranges = &DMA;
    for broken in [
        super::SdhciDevice {
            config: super::MmioWindow {
                base: device.host.base,
                ..device.config
            },
            ..device
        },
        super::SdhciDevice {
            gpio_widths: [15, 6],
            ..device
        },
        super::SdhciDevice {
            clock_hz: 0,
            ..device
        },
    ] {
        io.sdhci = Some(broken);
        assert_eq!(build(io), Err(Error::InvalidInput));
    }
}

#[test]
fn virtual_pci_ecam_resources_and_intx_map_are_guest_owned() -> Result<(), &'static str> {
    let bus = super::VirtualPci {
        ecam: super::MmioWindow {
            base: 0x0a80_0000,
            size: MIB,
        },
        memory: super::MmioWindow {
            base: 0x0a00_0000,
            size: MIB,
        },
        interrupts: &[(1, 48), (2, 49)],
    };
    let io = IoDevices {
        virtual_pci: Some(bus),
        ..IoDevices::empty()
    };
    let tree = build(io).map_err(|_| "build virtual PCI")?;
    let values = properties(&tree)?;
    assert_eq!(
        values.get("/pcie@a800000/compatible").map(Vec::as_slice),
        Some(b"pci-host-ecam-generic\0".as_slice())
    );
    assert_eq!(
        values
            .get("/intc@8000000/#address-cells")
            .map(Vec::as_slice),
        Some(0u32.to_be_bytes().as_slice())
    );
    let expected: Vec<u8> = [
        0x800u32,
        0,
        0,
        1,
        crate::guest_fdt::GIC_PHANDLE,
        0,
        16,
        4,
        0x1000,
        0,
        0,
        1,
        crate::guest_fdt::GIC_PHANDLE,
        0,
        17,
        4,
    ]
    .into_iter()
    .flat_map(u32::to_be_bytes)
    .collect();
    assert_eq!(values.get("/pcie@a800000/interrupt-map"), Some(&expected));
    assert!(!values.contains_key("/virtio_mmio@a000000/compatible"));
    assert!(
        build(IoDevices {
            virtual_pci: Some(super::VirtualPci {
                memory: bus.ecam,
                ..bus
            }),
            ..IoDevices::empty()
        })
        .is_err()
    );
    assert!(
        build(IoDevices {
            virtual_pci: Some(bus),
            virtio: Some(MmioDevice {
                base: 0x0a00_0000,
                size: 4096,
                irq: 48
            }),
            ..IoDevices::empty()
        })
        .is_err()
    );
    Ok(())
}
