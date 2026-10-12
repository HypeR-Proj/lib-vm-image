// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Validation of the raw `AArch64` Linux `Image` header and placement.

use super::{Architecture, Compression, ConfiguredImage, Payload, PlatformProfile, ReadAt};

const HEADER_SIZE: usize = 64;
const TEXT_OFFSET: usize = 8;
const IMAGE_SIZE: usize = 16;
const MAGIC: usize = 56;
const LINUX_IMAGE_MAGIC: u32 = 0x644d_5241;
const PLACEMENT_ALIGNMENT: u64 = 2 * 1024 * 1024;
/// Smallest RAM extent accepted by the initial reference platform.
pub const MINIMUM_REFERENCE_MEMORY_SIZE: u64 = 64 * 1024 * 1024;
/// Guest-physical start of RAM in the initial reference platform.
pub const REFERENCE_GUEST_RAM_BASE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GUEST_RAM_BASE;
/// Guest-physical address at which the runtime publishes the generated DTB.
pub const REFERENCE_DTB_ADDRESS: u64 = REFERENCE_GUEST_RAM_BASE
    + hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_DTB_OFFSET;
/// Memory reserved for the generated DTB when validating payload overlap,
/// including a bounded firmware subtree for a whole assigned PCI function.
pub const REFERENCE_DTB_RESERVED_SIZE: u64 = 128 * 1024;

/// A validated raw Linux image and the complete guest-physical range which it
/// reserves while running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageHeader {
    load_address: u64,
    text_offset: u64,
    occupied_size: u64,
    occupied_end: u64,
}

impl ImageHeader {
    #[must_use]
    pub const fn load_address(self) -> u64 {
        self.load_address
    }

    #[must_use]
    pub const fn text_offset(self) -> u64 {
        self.text_offset
    }

    #[must_use]
    pub const fn occupied_size(self) -> u64 {
        self.occupied_size
    }

    #[must_use]
    pub const fn occupied_end(self) -> u64 {
        self.occupied_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<SourceError> {
    Source(SourceError),
    CompressedPayload,
    PayloadTooSmall,
    PayloadOutOfBounds,
    InvalidMagic,
    MissingOccupiedSize,
    OccupiedSizeTooSmall,
    InvalidEntry,
    InvalidPlacement,
    AddressOverflow,
}

pub use crate::placement::AddressRange;

/// Complete validated placement for the `AArch64` reference Linux platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceLayout {
    kernel: ImageHeader,
    initramfs: Option<AddressRange>,
    device_tree: AddressRange,
}

impl ReferenceLayout {
    #[must_use]
    pub const fn kernel(self) -> ImageHeader {
        self.kernel
    }

    #[must_use]
    pub const fn initramfs(self) -> Option<AddressRange> {
        self.initramfs
    }

    #[must_use]
    pub const fn device_tree(self) -> AddressRange {
        self.device_tree
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayoutError<SourceError> {
    Source(SourceError),
    Kernel(Error<SourceError>),
    UnsupportedArchitecture,
    UnsupportedPlatformProfile,
    UnsupportedVcpuCount,
    InvalidMemorySize,
    InvalidPayload,
    PayloadOutOfBounds,
    OverlappingPayloads,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementError {
    InvalidMemorySize,
    InvalidPayload,
    AddressOverflow,
}

enum MemorySizeError {
    Invalid,
    AddressOverflow,
}

/// Validates a raw `AArch64` Linux `Image` selected from a FIT.
///
/// `image_size` is the authoritative in-memory extent, which can exceed the
/// embedded payload length. A zero `image_size` denotes a legacy image whose
/// occupied range cannot be established safely and is deliberately rejected.
pub fn validate<Source: ReadAt>(
    source: &Source,
    payload: Payload,
) -> Result<ImageHeader, Error<Source::Error>> {
    if payload.compression != Compression::None {
        return Err(Error::CompressedPayload);
    }
    if payload.length < HEADER_SIZE as u64 {
        return Err(Error::PayloadTooSmall);
    }
    let payload_end = payload
        .file_offset
        .checked_add(payload.length)
        .ok_or(Error::AddressOverflow)?;
    let source_length = source.length().map_err(Error::Source)?;
    if payload_end > source_length {
        return Err(Error::PayloadOutOfBounds);
    }

    let mut bytes = [0u8; HEADER_SIZE];
    source
        .read_exact_at(payload.file_offset, &mut bytes)
        .map_err(Error::Source)?;
    if le32(&bytes, MAGIC) != Some(LINUX_IMAGE_MAGIC) {
        return Err(Error::InvalidMagic);
    }

    let text_offset = le64(&bytes, TEXT_OFFSET).ok_or(Error::InvalidMagic)?;
    let occupied_size = le64(&bytes, IMAGE_SIZE).ok_or(Error::InvalidMagic)?;
    if occupied_size == 0 {
        return Err(Error::MissingOccupiedSize);
    }
    if occupied_size < payload.length {
        return Err(Error::OccupiedSizeTooSmall);
    }
    if payload.entry_address != payload.load_address {
        return Err(Error::InvalidEntry);
    }
    let placement_base = payload
        .load_address
        .checked_sub(text_offset)
        .ok_or(Error::InvalidPlacement)?;
    if !placement_base.is_multiple_of(PLACEMENT_ALIGNMENT) {
        return Err(Error::InvalidPlacement);
    }
    let occupied_end = payload
        .load_address
        .checked_add(occupied_size)
        .ok_or(Error::AddressOverflow)?;

    Ok(ImageHeader {
        load_address: payload.load_address,
        text_offset,
        occupied_size,
        occupied_end,
    })
}

/// Validates every image and placement invariant of the initial `AArch64` board.
///
/// Image composition and runtime loading share this function, so their memory
/// contracts cannot drift independently.
pub fn validate_reference<Source: ReadAt>(
    source: &Source,
    image: ConfiguredImage,
) -> Result<ReferenceLayout, ReferenceLayoutError<Source::Error>> {
    if image.architecture != Architecture::Aarch64 {
        return Err(ReferenceLayoutError::UnsupportedArchitecture);
    }
    if image.platform_profile != PlatformProfile::Aarch64Reference {
        return Err(ReferenceLayoutError::UnsupportedPlatformProfile);
    }
    if !(1..=hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_MAX_VCPUS)
        .contains(&u64::from(image.vcpu_count))
    {
        return Err(ReferenceLayoutError::UnsupportedVcpuCount);
    }
    let memory_end = reference_memory_end(image.memory_size).map_err(|error| match error {
        MemorySizeError::Invalid => ReferenceLayoutError::InvalidMemorySize,
        MemorySizeError::AddressOverflow => ReferenceLayoutError::AddressOverflow,
    })?;
    let kernel = validate(source, image.kernel).map_err(ReferenceLayoutError::Kernel)?;
    let placement_base = kernel
        .load_address()
        .checked_sub(kernel.text_offset())
        .ok_or(ReferenceLayoutError::AddressOverflow)?;
    let device_tree = AddressRange {
        start: REFERENCE_DTB_ADDRESS,
        end: REFERENCE_DTB_ADDRESS
            .checked_add(REFERENCE_DTB_RESERVED_SIZE)
            .ok_or(ReferenceLayoutError::AddressOverflow)?,
    };
    let initramfs = crate::placement::validate(
        source,
        image,
        AddressRange {
            start: REFERENCE_GUEST_RAM_BASE,
            end: memory_end,
        },
        AddressRange {
            start: kernel.load_address(),
            end: kernel.occupied_end(),
        },
        placement_base,
        device_tree,
    )
    .map_err(map_placement_error)?;
    Ok(ReferenceLayout {
        kernel,
        initramfs,
        device_tree,
    })
}

fn map_placement_error<E>(error: crate::placement::Error<E>) -> ReferenceLayoutError<E> {
    use crate::placement::Error;
    match error {
        Error::Source(error) => ReferenceLayoutError::Source(error),
        Error::InvalidPayload => ReferenceLayoutError::InvalidPayload,
        Error::InvalidMemorySize => ReferenceLayoutError::InvalidMemorySize,
        Error::PayloadOutOfBounds => ReferenceLayoutError::PayloadOutOfBounds,
        Error::OverlappingPayloads => ReferenceLayoutError::OverlappingPayloads,
        Error::AddressOverflow => ReferenceLayoutError::AddressOverflow,
    }
}

/// Chooses the canonical top-of-RAM placement used by the development packer.
///
/// Final validation remains mandatory because the kernel's occupied extent can
/// overlap a top-placed initramfs even when both individually fit in RAM.
pub fn plan_initramfs_load(memory_size: u64, initramfs_length: u64) -> Result<u64, PlacementError> {
    crate::placement::plan_initramfs::<core::convert::Infallible>(
        REFERENCE_GUEST_RAM_BASE,
        memory_size,
        MINIMUM_REFERENCE_MEMORY_SIZE,
        initramfs_length,
    )
    .map_err(|error| match error {
        crate::placement::Error::InvalidMemorySize => PlacementError::InvalidMemorySize,
        crate::placement::Error::AddressOverflow => PlacementError::AddressOverflow,
        _ => PlacementError::InvalidPayload,
    })
}

fn reference_memory_end(memory_size: u64) -> Result<u64, MemorySizeError> {
    crate::placement::memory_end::<core::convert::Infallible>(
        REFERENCE_GUEST_RAM_BASE,
        memory_size,
        MINIMUM_REFERENCE_MEMORY_SIZE,
    )
    .map_err(|error| match error {
        crate::placement::Error::AddressOverflow => MemorySizeError::AddressOverflow,
        _ => MemorySizeError::Invalid,
    })
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    let array: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    let array: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootArguments, ConfiguredImage, PlatformProfile};

    const FILE_OFFSET: usize = 16;
    const PAYLOAD_LENGTH: usize = HEADER_SIZE + 16;

    struct Source([u8; FILE_OFFSET + PAYLOAD_LENGTH]);

    impl Source {
        fn image(text_offset: u64, image_size: u64) -> Self {
            let mut bytes = [0u8; FILE_OFFSET + PAYLOAD_LENGTH];
            bytes[FILE_OFFSET + TEXT_OFFSET..FILE_OFFSET + TEXT_OFFSET + 8]
                .copy_from_slice(&text_offset.to_le_bytes());
            bytes[FILE_OFFSET + IMAGE_SIZE..FILE_OFFSET + IMAGE_SIZE + 8]
                .copy_from_slice(&image_size.to_le_bytes());
            bytes[FILE_OFFSET + MAGIC..FILE_OFFSET + MAGIC + 4]
                .copy_from_slice(&LINUX_IMAGE_MAGIC.to_le_bytes());
            Self(bytes)
        }

        const fn payload(load_address: u64) -> Payload {
            Payload {
                file_offset: FILE_OFFSET as u64,
                length: PAYLOAD_LENGTH as u64,
                load_address,
                entry_address: load_address,
                compression: Compression::None,
            }
        }
    }

    impl ReadAt for Source {
        type Error = ();

        fn length(&self) -> Result<u64, Self::Error> {
            Ok(self.0.len() as u64)
        }

        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let end = start.checked_add(output.len()).ok_or(())?;
            output.copy_from_slice(self.0.get(start..end).ok_or(())?);
            Ok(())
        }
    }

    #[test]
    fn validates_occupied_extent_and_text_offset_placement() {
        let source = Source::image(0x0008_0000, 0x0018_0000);
        let result = validate(&source, Source::payload(0x4008_0000));
        assert_eq!(
            result,
            Ok(ImageHeader {
                load_address: 0x4008_0000,
                text_offset: 0x0008_0000,
                occupied_size: 0x0018_0000,
                occupied_end: 0x4020_0000,
            })
        );
    }

    #[test]
    fn rejects_bad_magic_and_legacy_zero_size() {
        let mut bad_magic = Source::image(0, PAYLOAD_LENGTH as u64);
        bad_magic.0[FILE_OFFSET + MAGIC] ^= 1;
        assert!(matches!(
            validate(&bad_magic, Source::payload(0x4020_0000)),
            Err(Error::InvalidMagic)
        ));

        let zero_size = Source::image(0, 0);
        assert!(matches!(
            validate(&zero_size, Source::payload(0x4020_0000)),
            Err(Error::MissingOccupiedSize)
        ));
    }

    #[test]
    fn rejects_an_extent_smaller_than_the_embedded_payload() {
        let source = Source::image(0, (PAYLOAD_LENGTH - 1) as u64);
        assert!(matches!(
            validate(&source, Source::payload(0x4020_0000)),
            Err(Error::OccupiedSizeTooSmall)
        ));
    }

    #[test]
    fn rejects_truncated_and_overflowing_ranges() {
        let source = Source::image(0, PAYLOAD_LENGTH as u64);
        let mut truncated = Source::payload(0x4020_0000);
        truncated.length += 1;
        assert!(matches!(
            validate(&source, truncated),
            Err(Error::PayloadOutOfBounds)
        ));

        let overflowing = Source::image(0, PLACEMENT_ALIGNMENT);
        let highest_aligned_address = u64::MAX - (PLACEMENT_ALIGNMENT - 1);
        assert!(matches!(
            validate(&overflowing, Source::payload(highest_aligned_address)),
            Err(Error::AddressOverflow)
        ));
    }

    #[test]
    fn rejects_an_entry_or_placement_which_violates_the_boot_protocol() {
        let source = Source::image(0, PAYLOAD_LENGTH as u64);
        let mut wrong_entry = Source::payload(0x4020_0000);
        wrong_entry.entry_address += 4;
        assert!(matches!(
            validate(&source, wrong_entry),
            Err(Error::InvalidEntry)
        ));
        assert!(matches!(
            validate(&source, Source::payload(0x4020_1000)),
            Err(Error::InvalidPlacement)
        ));
    }

    #[test]
    fn validates_the_complete_reference_layout() {
        let source = Source::image(0x0008_0000, 0x0018_0000);
        let image = reference_image(Source::payload(0x4008_0000));
        let layout = validate_reference(&source, image);
        assert!(
            matches!(layout, Ok(layout) if layout.kernel().occupied_end() == 0x4020_0000
            && layout.device_tree().end() - layout.device_tree().start() == 128 * 1024)
        );
    }

    #[test]
    fn plans_and_validates_a_top_placed_initramfs() {
        let load = plan_initramfs_load(MINIMUM_REFERENCE_MEMORY_SIZE, 16);
        assert_eq!(load, Ok(0x43ff_f000));

        let source = Source::image(0x0008_0000, 0x0018_0000);
        let mut image = reference_image(Source::payload(0x4008_0000));
        image.initramfs = Some(Payload {
            file_offset: 0,
            length: 16,
            load_address: 0x43ff_f000,
            entry_address: 0x43ff_f000,
            compression: Compression::Gzip,
        });
        assert!(validate_reference(&source, image).is_ok());
    }

    #[test]
    fn rejects_an_initramfs_outside_the_source() {
        let source = Source::image(0x0008_0000, 0x0018_0000);
        let mut image = reference_image(Source::payload(0x4008_0000));
        image.initramfs = Some(Payload {
            file_offset: source.0.len() as u64,
            length: 1,
            load_address: 0x43ff_f000,
            entry_address: 0x43ff_f000,
            compression: Compression::Gzip,
        });
        assert!(matches!(
            validate_reference(&source, image),
            Err(ReferenceLayoutError::PayloadOutOfBounds)
        ));

        image.initramfs = Some(Payload {
            file_offset: u64::MAX,
            length: 2,
            load_address: 0x43ff_f000,
            entry_address: 0x43ff_f000,
            compression: Compression::Gzip,
        });
        assert!(matches!(
            validate_reference(&source, image),
            Err(ReferenceLayoutError::AddressOverflow)
        ));
    }

    #[test]
    fn rejects_reference_payload_overlap() {
        let source = Source::image(0x0008_0000, 0x0018_0000);
        let mut image = reference_image(Source::payload(0x4008_0000));
        image.initramfs = Some(Payload {
            file_offset: 0,
            length: 16,
            load_address: 0x4010_0000,
            entry_address: 0x4010_0000,
            compression: Compression::Gzip,
        });
        assert!(matches!(
            validate_reference(&source, image),
            Err(ReferenceLayoutError::OverlappingPayloads)
        ));
    }

    #[test]
    fn rejects_a_kernel_placement_base_outside_guest_ram() {
        let source = Source::image(0x4008_0000, 0x0018_0000);
        let image = reference_image(Source::payload(0x4008_0000));
        assert!(matches!(
            validate_reference(&source, image),
            Err(ReferenceLayoutError::InvalidPayload)
        ));
    }

    #[test]
    fn accepts_bounded_smp_and_preserves_boot_topology() -> Result<(), crate::linux::Error<()>> {
        let source = Source::image(0x0008_0000, 0x0018_0000);
        for count in [0, 1, 2, 4, 8, 9] {
            let mut image = reference_image(Source::payload(0x4008_0000));
            image.vcpu_count = count;
            if (1..=8).contains(&count) {
                let plan = crate::linux::validate_reference(&source, image)?;
                assert_eq!(plan.vcpu_count(), count);
            } else {
                assert!(matches!(
                    validate_reference(&source, image),
                    Err(ReferenceLayoutError::UnsupportedVcpuCount)
                ));
            }
        }
        Ok(())
    }

    fn reference_image(kernel: Payload) -> ConfiguredImage {
        ConfiguredImage {
            architecture: Architecture::Aarch64,
            platform_profile: PlatformProfile::Aarch64Reference,
            memory_size: MINIMUM_REFERENCE_MEMORY_SIZE,
            vcpu_count: 1,
            kernel,
            initramfs: None,
            boot_arguments: BootArguments::empty(),
        }
    }
}
