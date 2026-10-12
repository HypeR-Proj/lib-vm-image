// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Shared checked Linux payload geometry, independent of image-header syntax.

use crate::{ConfiguredImage, ReadAt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}
impl AddressRange {
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error<E> {
    Source(E),
    InvalidPayload,
    InvalidMemorySize,
    PayloadOutOfBounds,
    OverlappingPayloads,
    AddressOverflow,
}

pub(crate) fn memory_end<E>(base: u64, size: u64, minimum: u64) -> Result<u64, Error<E>> {
    if size < minimum || !size.is_power_of_two() || !size.is_multiple_of(4096) {
        return Err(Error::InvalidMemorySize);
    }
    base.checked_add(size).ok_or(Error::AddressOverflow)
}

pub(crate) fn plan_initramfs<E>(
    base: u64,
    size: u64,
    minimum: u64,
    length: u64,
) -> Result<u64, Error<E>> {
    if length == 0 {
        return Err(Error::InvalidPayload);
    }
    let end = memory_end(base, size, minimum)?;
    let start = end.checked_sub(length).ok_or(Error::InvalidPayload)? & !4095;
    if start < base {
        return Err(Error::InvalidPayload);
    }
    Ok(start)
}

pub(crate) fn validate<Source: ReadAt>(
    source: &Source,
    image: ConfiguredImage,
    memory: AddressRange,
    kernel: AddressRange,
    placement_base: u64,
    device_tree: AddressRange,
) -> Result<Option<AddressRange>, Error<Source::Error>> {
    if placement_base < memory.start || !contains(memory, kernel) {
        return Err(Error::InvalidPayload);
    }
    if !contains(memory, device_tree) {
        return Err(Error::InvalidMemorySize);
    }
    if overlaps(device_tree, kernel) {
        return Err(Error::OverlappingPayloads);
    }
    let initramfs = image
        .initramfs
        .map(|payload| {
            let source_end = payload
                .file_offset
                .checked_add(payload.length)
                .ok_or(Error::AddressOverflow)?;
            if source_end > source.length().map_err(Error::Source)? {
                return Err(Error::PayloadOutOfBounds);
            }
            let end = payload
                .load_address
                .checked_add(payload.length)
                .ok_or(Error::AddressOverflow)?;
            let range = AddressRange {
                start: payload.load_address,
                end,
            };
            if payload.length == 0
                || !contains(memory, range)
                || payload.entry_address < range.start
                || payload.entry_address >= range.end
            {
                return Err(Error::InvalidPayload);
            }
            Ok(range)
        })
        .transpose()?;
    if initramfs.is_some_and(|range| overlaps(range, kernel) || overlaps(range, device_tree)) {
        return Err(Error::OverlappingPayloads);
    }
    Ok(initramfs)
}

const fn contains(outer: AddressRange, inner: AddressRange) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}
const fn overlaps(first: AddressRange, second: AddressRange) -> bool {
    first.start < second.end && second.start < first.end
}
