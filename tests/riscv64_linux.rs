// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone)]
struct Source([u8; 128]);
impl Source {
    fn valid() -> Self {
        let mut source = Self([0; 128]);
        source.0[8..16].copy_from_slice(&0x20_0000u64.to_le_bytes());
        source.0[16..24].copy_from_slice(&0x30_0000u64.to_le_bytes());
        source.0[32..36].copy_from_slice(&2u32.to_le_bytes());
        source.0[56..60].copy_from_slice(b"RSC\x05");
        source
    }
    fn image() -> ConfiguredImage {
        ConfiguredImage {
            architecture: Architecture::Riscv64,
            platform_profile: PlatformProfile::Riscv64Reference,
            memory_size: 128 * 1024 * 1024,
            vcpu_count: 1,
            kernel: Payload {
                file_offset: 0,
                length: 64,
                load_address: 0x8020_0000,
                entry_address: 0x8020_0000,
                compression: Compression::None,
            },
            initramfs: None,
            boot_arguments: crate::BootArguments::empty(),
        }
    }
}
impl ReadAt for Source {
    type Error = ();
    fn length(&self) -> Result<u64, ()> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ()> {
        let offset = usize::try_from(offset).map_err(|_| ())?;
        let end = offset.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.0.get(offset..end).ok_or(())?);
        Ok(())
    }
}

#[test]
fn image_bss_extent_and_rv_boot_registers_are_preserved() -> Result<(), crate::linux::Error<()>> {
    let plan = crate::linux::validate_reference(&Source::valid(), Source::image())?;
    assert_eq!(plan.kernel_occupied_range().end(), 0x8050_0000);
    assert_eq!(plan.kernel_load_address(), 0x8020_0000);
    assert_eq!(plan.bootstrap_arguments(), [0, 0x8001_0000, 0, 0]);
    assert_eq!(plan.memory_base(), 0x8000_0000);
    Ok(())
}

#[test]
fn versioned_magic_ignores_deprecated_field_but_rejects_unknown_semantics() {
    let image = Source::image();
    let mut source = Source::valid();
    source.0[48..56].fill(0xff); // Deprecated first magic is not required.
    source.0[60..64].copy_from_slice(&64u32.to_le_bytes()); // Optional EFI offset.
    source.0[32..36].copy_from_slice(&3u32.to_le_bytes());
    assert!(validate(&source, image.kernel).is_ok());
    for version in [0u32, 1, 0x10002] {
        source.0[32..36].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            validate(&source, image.kernel),
            Err(Error::UnsupportedVersion)
        );
    }
    for flags in [1u64, 2, 1 << 63] {
        let mut source = Source::valid();
        source.0[24..32].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            validate(&source, image.kernel),
            Err(Error::UnsupportedFlags)
        );
    }
}

#[test]
fn malformed_headers_and_unrepresentable_placement_are_rejected() {
    let mut source = Source::valid();
    let mut payload = Source::image().kernel;
    payload.length = 63;
    assert_eq!(validate(&source, payload), Err(Error::PayloadTooSmall));
    payload.length = 129;
    assert_eq!(validate(&source, payload), Err(Error::PayloadOutOfBounds));
    payload = Source::image().kernel;
    source.0[56] = 0;
    assert_eq!(validate(&source, payload), Err(Error::InvalidMagic));
    for size in [0u64, 63] {
        let mut source = Source::valid();
        source.0[16..24].copy_from_slice(&size.to_le_bytes());
        assert!(matches!(
            validate(&source, payload),
            Err(Error::MissingOccupiedSize | Error::OccupiedSizeTooSmall)
        ));
    }
    let source = Source::valid();
    payload.load_address += 4096;
    payload.entry_address = payload.load_address;
    assert_eq!(validate(&source, payload), Err(Error::InvalidPlacement));
    payload.load_address = !0x1f_ffffu64;
    payload.entry_address = payload.load_address;
    assert_eq!(validate(&source, payload), Err(Error::AddressOverflow));
}

#[test]
fn shared_layout_rejects_bss_and_device_tree_collisions() {
    let source = Source::valid();
    let mut image = Source::image();
    image.initramfs = Some(Payload {
        file_offset: 64,
        length: 64,
        load_address: 0x8040_0000,
        entry_address: 0x8040_0000,
        compression: Compression::Gzip,
    });
    assert_eq!(
        validate_reference(&source, image),
        Err(ReferenceLayoutError::OverlappingPayloads)
    );
    let mut source = source;
    source.0[8..16].fill(0);
    image.initramfs = None;
    image.kernel.load_address = REFERENCE_GUEST_RAM_BASE;
    image.kernel.entry_address = REFERENCE_GUEST_RAM_BASE;
    assert_eq!(
        validate_reference(&source, image),
        Err(ReferenceLayoutError::OverlappingPayloads)
    );
    image = Source::image();
    image.vcpu_count = 2;
    assert_eq!(
        validate_reference(&source, image),
        Err(ReferenceLayoutError::UnsupportedVcpuCount)
    );
    image.vcpu_count = 1;
    image.platform_profile = PlatformProfile::Aarch64Reference;
    assert_eq!(
        validate_reference(&source, image),
        Err(ReferenceLayoutError::UnsupportedPlatformProfile)
    );
}

#[test]
fn initramfs_planning_checks_memory_and_keeps_page_alignment() {
    use crate::linux::{PlacementError, plan_initramfs_load};
    let plan = |size, length| {
        plan_initramfs_load(
            Architecture::Riscv64,
            PlatformProfile::Riscv64Reference,
            size,
            length,
        )
    };
    assert_eq!(plan(128 * 1024 * 1024, 4097), Ok(0x87ff_e000));
    assert_eq!(
        plan(32 * 1024 * 1024, 4096),
        Err(PlacementError::InvalidMemorySize)
    );
    assert_eq!(
        plan(128 * 1024 * 1024, 0),
        Err(PlacementError::InvalidPayload)
    );
    assert_eq!(
        plan(128 * 1024 * 1024, u64::MAX),
        Err(PlacementError::InvalidPayload)
    );
}

#[path = "riscv64_fdt.rs"]
mod fdt;
