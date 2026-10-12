// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Checked RV64 Linux Image headers and reference-board placement.
//! Header and boot contracts: <https://docs.kernel.org/arch/riscv/boot-image-header.html>
//! and <https://docs.kernel.org/arch/riscv/boot.html>.

use crate::placement::{self, AddressRange};
use crate::{Architecture, Compression, ConfiguredImage, Payload, PlatformProfile, ReadAt};

pub const REFERENCE_GUEST_RAM_BASE: u64 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_GUEST_RAM_BASE;
pub const REFERENCE_DTB_ADDRESS: u64 = REFERENCE_GUEST_RAM_BASE
    + hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_DTB_OFFSET;
pub const REFERENCE_DTB_RESERVED_SIZE: u64 = 16 * 1024;
pub const MINIMUM_REFERENCE_MEMORY_SIZE: u64 = 64 * 1024 * 1024;
const ALIGNMENT: u64 = 2 * 1024 * 1024;

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
pub enum Error<E> {
    Source(E),
    CompressedPayload,
    PayloadTooSmall,
    PayloadOutOfBounds,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    MissingOccupiedSize,
    OccupiedSizeTooSmall,
    InvalidEntry,
    InvalidPlacement,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayoutError<E> {
    Source(E),
    Kernel(Error<E>),
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

/// Validates the decompressed file extent separately from the larger in-memory
/// Image extent (including BSS). Version 0.2 introduced the stable second magic;
/// its deprecated first magic and optional PE/COFF offset are not prerequisites.
pub fn validate<S: ReadAt>(source: &S, payload: Payload) -> Result<ImageHeader, Error<S::Error>> {
    if payload.compression != Compression::None {
        return Err(Error::CompressedPayload);
    }
    if payload.length < 64 {
        return Err(Error::PayloadTooSmall);
    }
    let end = payload
        .file_offset
        .checked_add(payload.length)
        .ok_or(Error::AddressOverflow)?;
    if end > source.length().map_err(Error::Source)? {
        return Err(Error::PayloadOutOfBounds);
    }
    let mut header = [0; 64];
    source
        .read_exact_at(payload.file_offset, &mut header)
        .map_err(Error::Source)?;
    if header[56..60] != *b"RSC\x05" {
        return Err(Error::InvalidMagic);
    }
    let version = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
    if version >> 16 != 0 || version & 0xffff < 2 {
        return Err(Error::UnsupportedVersion);
    }
    if le64(&header, 24) != 0 {
        return Err(Error::UnsupportedFlags);
    }
    let text_offset = le64(&header, 8);
    let occupied_size = le64(&header, 16);
    if occupied_size == 0 {
        return Err(Error::MissingOccupiedSize);
    }
    if occupied_size < payload.length {
        return Err(Error::OccupiedSizeTooSmall);
    }
    if payload.entry_address != payload.load_address {
        return Err(Error::InvalidEntry);
    }
    let base = payload
        .load_address
        .checked_sub(text_offset)
        .ok_or(Error::InvalidPlacement)?;
    if !payload.load_address.is_multiple_of(ALIGNMENT) || !base.is_multiple_of(ALIGNMENT) {
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

pub fn validate_reference<S: ReadAt>(
    source: &S,
    image: ConfiguredImage,
) -> Result<ReferenceLayout, ReferenceLayoutError<S::Error>> {
    if image.architecture != Architecture::Riscv64 {
        return Err(ReferenceLayoutError::UnsupportedArchitecture);
    }
    if image.platform_profile != PlatformProfile::Riscv64Reference {
        return Err(ReferenceLayoutError::UnsupportedPlatformProfile);
    }
    if image.vcpu_count != 1 {
        return Err(ReferenceLayoutError::UnsupportedVcpuCount);
    }
    let memory_end = placement::memory_end(
        REFERENCE_GUEST_RAM_BASE,
        image.memory_size,
        MINIMUM_REFERENCE_MEMORY_SIZE,
    )
    .map_err(map_placement)?;
    let kernel = validate(source, image.kernel).map_err(ReferenceLayoutError::Kernel)?;
    let base = kernel
        .load_address
        .checked_sub(kernel.text_offset)
        .ok_or(ReferenceLayoutError::AddressOverflow)?;
    let device_tree = AddressRange {
        start: REFERENCE_DTB_ADDRESS,
        end: REFERENCE_DTB_ADDRESS
            .checked_add(REFERENCE_DTB_RESERVED_SIZE)
            .ok_or(ReferenceLayoutError::AddressOverflow)?,
    };
    let initramfs = placement::validate(
        source,
        image,
        AddressRange {
            start: REFERENCE_GUEST_RAM_BASE,
            end: memory_end,
        },
        AddressRange {
            start: kernel.load_address,
            end: kernel.occupied_end,
        },
        base,
        device_tree,
    )
    .map_err(map_placement)?;
    Ok(ReferenceLayout {
        kernel,
        initramfs,
        device_tree,
    })
}

fn map_placement<E>(error: placement::Error<E>) -> ReferenceLayoutError<E> {
    match error {
        placement::Error::Source(error) => ReferenceLayoutError::Source(error),
        placement::Error::InvalidPayload => ReferenceLayoutError::InvalidPayload,
        placement::Error::InvalidMemorySize => ReferenceLayoutError::InvalidMemorySize,
        placement::Error::PayloadOutOfBounds => ReferenceLayoutError::PayloadOutOfBounds,
        placement::Error::OverlappingPayloads => ReferenceLayoutError::OverlappingPayloads,
        placement::Error::AddressOverflow => ReferenceLayoutError::AddressOverflow,
    }
}

fn le64(bytes: &[u8; 64], offset: usize) -> u64 {
    let mut value = 0;
    for index in 0..8 {
        value |= u64::from(bytes[offset + index]) << (index * 8);
    }
    value
}

#[cfg(test)]
#[path = "../tests/riscv64_linux.rs"]
mod tests;
