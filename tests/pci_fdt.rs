// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::std::vec::Vec;
use super::{DMA, build, devices, properties};
use crate::guest_fdt::Error;
use crate::guest_fdt::io::{
    FirmwareNode, FirmwareProperty, IoDevices, MmioWindow, PciBar, PciHost,
};

const BARS: [PciBar; 3] = [
    PciBar {
        index: 0,
        window: MmioWindow {
            base: 0x0ba0_0000,
            size: 0x4000,
        },
        bus_address: 0x20_0000,
        memory64: false,
        prefetchable: false,
    },
    PciBar {
        index: 1,
        window: MmioWindow {
            base: 0x0bc0_0000,
            size: 0x40_0000,
        },
        bus_address: 0x40_0000,
        memory64: false,
        prefetchable: false,
    },
    PciBar {
        index: 2,
        window: MmioWindow {
            base: 0x0ba1_0000,
            size: 0x1_0000,
        },
        bus_address: 0x21_0000,
        memory64: false,
        prefetchable: false,
    },
];
fn host() -> PciHost<'static> {
    PciHost {
        aperture: MmioWindow {
            base: 0x0b80_0000,
            size: 0x80_0000,
        },
        ecam: MmioWindow {
            base: 0x0b80_0000,
            size: 0x10_0000,
        },
        msi: MmioWindow {
            base: 0x0b90_0000,
            size: 4096,
        },
        interrupt_base: 128,
        interrupt_count: 64,
        bars: &BARS,
        dma_bus_offset: 0x10_0000_0000,
        nodes: &[],
    }
}
fn with_pci(pci: PciHost<'_>) -> IoDevices<'_> {
    IoDevices {
        pci: Some(pci),
        ..devices()
    }
}
fn cells(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

#[test]
fn pci_host_preserves_bus_addresses_dma_translation_and_msi_vectors() -> Result<(), &'static str> {
    let values = properties(&build(with_pci(host())).map_err(|_| "build PCI")?)?;
    assert_eq!(
        values.get("/pcie@b800000/compatible"),
        Some(&b"pci-host-ecam-generic\0".to_vec())
    );
    assert_eq!(values.get("/pcie@b800000/bus-range"), Some(&cells(&[0, 0])));
    assert_eq!(
        values.get("/pcie@b800000/ranges"),
        Some(&cells(&[
            0x02000000, 0, 0x200000, 0, 0x0ba00000, 0, 0x4000, 0x02000000, 0, 0x400000, 0,
            0x0bc00000, 0, 0x400000, 0x02000000, 0, 0x210000, 0, 0x0ba10000, 0, 0x10000,
        ]))
    );
    let expected: Vec<_> = DMA
        .iter()
        .flat_map(|range| {
            let bus = range.dma_base + host().dma_bus_offset;
            [
                0x43000000,
                (bus >> 32) as u32,
                bus as u32,
                (range.cpu_base >> 32) as u32,
                range.cpu_base as u32,
                (range.size >> 32) as u32,
                range.size as u32,
            ]
        })
        .flat_map(u32::to_be_bytes)
        .collect();
    assert_eq!(values.get("/pcie@b800000/dma-ranges"), Some(&expected));
    assert_eq!(
        values.get("/intc@8000000/msi-controller@b900000/arm,msi-base-spi"),
        Some(&cells(&[128]))
    );
    assert_eq!(
        values.get("/intc@8000000/msi-controller@b900000/arm,msi-num-spis"),
        Some(&cells(&[64]))
    );
    assert_eq!(
        values.get("/pcie@b800000/msi-parent"),
        values.get("/intc@8000000/msi-controller@b900000/phandle")
    );
    assert!(!values.contains_key("/pcie@b800000/dma-coherent"));
    Ok(())
}

#[test]
fn pci_rejects_out_of_aperture_resources_bar_aliases_and_interrupt_overlap() {
    for pci in [
        PciHost {
            interrupt_count: 0,
            ..host()
        },
        PciHost {
            interrupt_count: 65,
            ..host()
        },
        PciHost {
            interrupt_base: 240,
            ..host()
        },
        PciHost {
            interrupt_base: 40,
            ..host()
        },
        PciHost {
            ecam: MmioWindow {
                base: 0x0b90_0000,
                size: 0x10_0000,
            },
            ..host()
        },
        PciHost {
            msi: MmioWindow {
                base: 0x0b90_0000,
                size: 8192,
            },
            ..host()
        },
        PciHost {
            aperture: MmioWindow {
                base: 0x0b80_0000,
                size: 0x100_0000,
            },
            ..host()
        },
    ] {
        assert_eq!(build(with_pci(pci)), Err(Error::InvalidInput));
    }
    for invalid in [
        PciBar {
            index: 1,
            ..BARS[0]
        },
        PciBar {
            window: BARS[1].window,
            ..BARS[0]
        },
        PciBar {
            memory64: true,
            ..BARS[0]
        },
        PciBar {
            bus_address: 0x1f00000000,
            ..BARS[0]
        },
        PciBar {
            window: MmioWindow {
                base: 0x0ba00000,
                size: 0x4001,
            },
            ..BARS[0]
        },
    ] {
        let bars = [invalid, BARS[1], BARS[2]];
        assert_eq!(
            build(with_pci(PciHost {
                bars: &bars,
                ..host()
            })),
            Err(Error::InvalidInput)
        );
    }
    assert_eq!(
        build(with_pci(PciHost {
            dma_bus_offset: !4095,
            ..host()
        })),
        Err(Error::AddressOverflow)
    );
    let mut io = with_pci(host());
    io.dma_ranges = &[];
    assert_eq!(build(io), Err(Error::InvalidInput));
}

#[test]
fn firmware_subtree_is_preserved_but_cannot_redefine_reserved_phandles() -> Result<(), &'static str>
{
    let properties_list = [
        FirmwareProperty {
            name: "compatible",
            value: b"vendor,pci-test\0",
        },
        FirmwareProperty {
            name: "phandle",
            value: &512u32.to_be_bytes(),
        },
    ];
    let children = [FirmwareNode {
        name: "endpoint@0",
        properties: &properties_list,
        children: &[],
    }];
    let values = properties(
        &build(with_pci(PciHost {
            nodes: &children,
            ..host()
        }))
        .map_err(|_| "firmware")?,
    )?;
    assert_eq!(
        values.get("/pcie@b800000/endpoint@0/compatible"),
        Some(&b"vendor,pci-test\0".to_vec())
    );
    for props in [
        &[FirmwareProperty {
            name: "phandle",
            value: &0u32.to_be_bytes(),
        }][..],
        &[FirmwareProperty {
            name: "phandle",
            value: &0xffff0001u32.to_be_bytes(),
        }][..],
        &[
            FirmwareProperty {
                name: "x",
                value: &[],
            },
            FirmwareProperty {
                name: "x",
                value: &[],
            },
        ][..],
    ] {
        let nodes = [FirmwareNode {
            name: "endpoint@0",
            properties: props,
            children: &[],
        }];
        assert_eq!(
            build(with_pci(PciHost {
                nodes: &nodes,
                ..host()
            })),
            Err(Error::InvalidInput)
        );
    }
    let duplicates = [
        children[0],
        FirmwareNode {
            name: "other@1",
            ..children[0]
        },
    ];
    assert_eq!(
        build(with_pci(PciHost {
            nodes: &duplicates,
            ..host()
        })),
        Err(Error::InvalidInput)
    );
    Ok(())
}

#[test]
fn firmware_projection_has_bounded_work_and_rejects_invalid_names() {
    let leaf = FirmwareNode {
        name: "node",
        properties: &[],
        children: &[],
    };
    for name in ["", "bad/name", "bad\0name"] {
        let nodes = [FirmwareNode { name, ..leaf }];
        assert_eq!(
            build(with_pci(PciHost {
                nodes: &nodes,
                ..host()
            })),
            Err(Error::InvalidInput)
        );
    }
    let too_many = [leaf; 257];
    assert_eq!(
        build(with_pci(PciHost {
            nodes: &too_many,
            ..host()
        })),
        Err(Error::InvalidInput)
    );
    let bytes = [0; 65536];
    let props = [FirmwareProperty {
        name: "large",
        value: &bytes,
    }];
    let nodes = [FirmwareNode {
        properties: &props,
        ..leaf
    }];
    assert_eq!(
        build(with_pci(PciHost {
            nodes: &nodes,
            ..host()
        })),
        Err(Error::InvalidInput)
    );
    let l0 = [leaf];
    let l1 = [FirmwareNode {
        children: &l0,
        ..leaf
    }];
    let l2 = [FirmwareNode {
        children: &l1,
        ..leaf
    }];
    let l3 = [FirmwareNode {
        children: &l2,
        ..leaf
    }];
    let l4 = [FirmwareNode {
        children: &l3,
        ..leaf
    }];
    let l5 = [FirmwareNode {
        children: &l4,
        ..leaf
    }];
    let l6 = [FirmwareNode {
        children: &l5,
        ..leaf
    }];
    let l7 = [FirmwareNode {
        children: &l6,
        ..leaf
    }];
    assert!(
        build(with_pci(PciHost {
            nodes: &l7,
            ..host()
        }))
        .is_ok()
    );
    let l8 = [FirmwareNode {
        children: &l7,
        ..leaf
    }];
    assert_eq!(
        build(with_pci(PciHost {
            nodes: &l8,
            ..host()
        })),
        Err(Error::InvalidInput)
    );
}

#[test]
fn pci_msi_frame_is_available_with_both_reference_gic_versions() -> Result<(), &'static str> {
    for gic_version in [2, 3] {
        let mut boot = super::boot();
        boot.gic_version = gic_version;
        let mut structure = [0; 8192];
        let mut strings = [0; 2048];
        let mut output = [0; 12288];
        let length = crate::guest_fdt::build_aarch64_linux_with_io(
            boot,
            with_pci(host()),
            &mut structure,
            &mut strings,
            &mut output,
        )
        .map_err(|_| "build MSI")?;
        let properties = properties(&output[..length])?;
        assert_eq!(
            properties.get("/intc@8000000/msi-controller@b900000/compatible"),
            Some(&b"arm,gic-v2m-frame\0".to_vec())
        );
    }
    Ok(())
}
