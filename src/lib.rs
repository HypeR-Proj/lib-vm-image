// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Allocation-free parsing of standard flattened image tree containers.
//!
//! Payload bytes remain in the source file. The parser returns checked
//! byte ranges so a VMM can stream them directly into a guest-memory VMO.

#![no_std]

pub mod aarch64_linux;
pub mod guest_fdt;
pub mod linux;
mod placement;
pub mod riscv64_linux;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const HEADER_SIZE: u64 = 40;
const SUPPORTED_FDT_VERSION: u32 = 17;
const MAX_NAME_BYTES: usize = 64;
const MAX_RESERVATION_RECORDS: usize = 64;
const MAX_STRUCTURE_DEPTH: u32 = 32;
const MAX_STRUCTURE_TOKENS: usize = 4096;
/// Storage contract required on the selected FIT configuration.
pub const GUEST_IMAGE_COMPATIBLE: &str = "hyper,guest-image-v2";
/// Configuration name of the initial `AArch64` immutable virtual board.
pub const AARCH64_REFERENCE_PROFILE: &str = "aarch64-reference";
/// Configuration name of the RV64 immutable virtual board.
pub const RISCV64_REFERENCE_PROFILE: &str = "riscv64-reference";
/// Maximum accepted command-line bytes, excluding any terminator.
pub const MAX_BOOT_ARGUMENT_BYTES: usize = 2048;

/// Random-access byte source used without requiring an allocation policy.
pub trait ReadAt {
    type Error;

    fn length(&self) -> Result<u64, Self::Error>;
    /// Fills the entire output from `offset`, or reports a source error.
    ///
    /// A short read, including premature EOF, must not be reported as success.
    /// On error the output may already contain a partially copied prefix.
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<SourceError> {
    Source(SourceError),
    InvalidHeader,
    InvalidStructure,
    InvalidString,
    MissingConfiguration,
    MissingProperty,
    DuplicateProperty,
    DuplicateNode,
    UnsupportedImage,
    ResourceLimit,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payload {
    pub file_offset: u64,
    pub length: u64,
    pub load_address: u64,
    pub entry_address: u64,
    pub compression: Compression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Gzip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    Aarch64,
    Riscv64,
    X86_64,
}

/// Immutable virtual hardware contract selected by one guest configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformProfile {
    Aarch64Reference,
    Riscv64Reference,
    X86_64Reference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootArguments {
    bytes: [u8; MAX_BOOT_ARGUMENT_BYTES],
    length: usize,
}

impl BootArguments {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_BOOT_ARGUMENT_BYTES],
            length: 0,
        }
    }

    /// Builds command-line bytes from external VM configuration.
    pub fn new(value: &str) -> Result<Self, ConfigurationError> {
        if value.len() > MAX_BOOT_ARGUMENT_BYTES || value.as_bytes().contains(&0) {
            return Err(ConfigurationError::InvalidBootArguments);
        }
        let mut result = Self::empty();
        result.bytes[..value.len()].copy_from_slice(value.as_bytes());
        result.length = value.len();
        Ok(result)
    }

    pub fn as_str(&self) -> &str {
        // Parsing accepts only UTF-8 input and preserves its exact bytes.
        let Ok(value) = core::str::from_utf8(self.as_bytes()) else {
            return "";
        };
        value
    }

    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.split_at(self.length).0
    }
}

/// Payload metadata only; VM policy never comes from the FIT container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestImage {
    pub architecture: Architecture,
    pub kernel: Payload,
    pub initramfs: Option<Payload>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub boot_arguments: BootArguments,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    InvalidBootArguments,
    InvalidVcpuCount,
    ArchitectureMismatch {
        image: Architecture,
        host: Architecture,
    },
    UnsupportedArchitecture,
    Placement(linux::PlacementError),
}

impl GuestImage {
    /// Reject foreign guests before planning memory or constructing a VM.
    pub fn configure_for_host(
        self,
        config: Configuration,
        host: Architecture,
    ) -> Result<ConfiguredImage, ConfigurationError> {
        if self.architecture != host {
            return Err(ConfigurationError::ArchitectureMismatch {
                image: self.architecture,
                host,
            });
        }
        self.configure(config)
    }

    /// Places the initramfs using the selected instance's RAM, before validation.
    pub fn configure(self, config: Configuration) -> Result<ConfiguredImage, ConfigurationError> {
        let platform_profile = match self.architecture {
            Architecture::Aarch64 => PlatformProfile::Aarch64Reference,
            Architecture::Riscv64 => PlatformProfile::Riscv64Reference,
            Architecture::X86_64 => return Err(ConfigurationError::UnsupportedArchitecture),
        };
        let max = match platform_profile {
            PlatformProfile::Aarch64Reference => {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_MAX_VCPUS
            }
            _ => 1,
        };
        if !(1..=max).contains(&u64::from(config.vcpu_count)) {
            return Err(ConfigurationError::InvalidVcpuCount);
        }
        let initramfs = self
            .initramfs
            .map(|mut payload| {
                payload.load_address = linux::plan_initramfs_load(
                    self.architecture,
                    platform_profile,
                    config.memory_size,
                    payload.length,
                )
                .map_err(ConfigurationError::Placement)?;
                payload.entry_address = payload.load_address;
                Ok(payload)
            })
            .transpose()?;
        Ok(ConfiguredImage {
            architecture: self.architecture,
            platform_profile,
            memory_size: config.memory_size,
            vcpu_count: config.vcpu_count,
            boot_arguments: config.boot_arguments,
            kernel: self.kernel,
            initramfs,
        })
    }
}

/// Payloads placed according to external policy; validate before allocating RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredImage {
    pub architecture: Architecture,
    pub platform_profile: PlatformProfile,
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub kernel: Payload,
    pub initramfs: Option<Payload>,
    pub boot_arguments: BootArguments,
}

struct Header {
    structure: u64,
    strings: u64,
    structure_size: u64,
    strings_size: u64,
}

#[derive(Clone, Copy)]
struct Name {
    bytes: [u8; MAX_NAME_BYTES],
    length: usize,
}

impl Name {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_NAME_BYTES],
            length: 0,
        }
    }

    fn equals(&self, value: &str) -> bool {
        self.as_bytes() == value.as_bytes()
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.split_at(self.length).0
    }
}

struct Selection {
    kernel: Name,
    ramdisk: Option<Name>,
}

#[derive(Clone, Copy)]
enum Section {
    Other,
    Images,
    Configurations,
}

/// Parses one embedded-data FIT without copying its payloads.
pub fn parse<Source: ReadAt>(source: &Source) -> Result<GuestImage, Error<Source::Error>> {
    let header = read_header(source)?;
    let selection = read_selection(source, &header)?;
    let (kernel, architecture) = read_image(source, &header, selection.kernel, true)?;
    let initramfs = match selection.ramdisk {
        Some(name) => {
            let (payload, ramdisk_architecture) = read_image(source, &header, name, false)?;
            if ramdisk_architecture != architecture {
                return Err(Error::UnsupportedImage);
            }
            Some(payload)
        }
        None => None,
    };
    Ok(GuestImage {
        architecture,
        kernel,
        initramfs,
    })
}

fn read_header<Source: ReadAt>(source: &Source) -> Result<Header, Error<Source::Error>> {
    let mut bytes = [0u8; HEADER_SIZE as usize];
    source.read_exact_at(0, &mut bytes).map_err(Error::Source)?;
    let file_size = source.length().map_err(Error::Source)?;
    if be32(&bytes, 0) != Some(FDT_MAGIC) {
        return Err(Error::InvalidHeader);
    }
    let total_size = u64::from(be32(&bytes, 4).ok_or(Error::InvalidHeader)?);
    let structure = u64::from(be32(&bytes, 8).ok_or(Error::InvalidHeader)?);
    let strings = u64::from(be32(&bytes, 12).ok_or(Error::InvalidHeader)?);
    let reservations = u64::from(be32(&bytes, 16).ok_or(Error::InvalidHeader)?);
    let version = be32(&bytes, 20).ok_or(Error::InvalidHeader)?;
    let last_compatible_version = be32(&bytes, 24).ok_or(Error::InvalidHeader)?;
    let strings_size = u64::from(be32(&bytes, 32).ok_or(Error::InvalidHeader)?);
    let structure_size = u64::from(be32(&bytes, 36).ok_or(Error::InvalidHeader)?);
    let structure_end = structure.checked_add(structure_size);
    let strings_end = strings.checked_add(strings_size);
    if total_size < HEADER_SIZE
        || total_size > file_size
        || version < SUPPORTED_FDT_VERSION
        || last_compatible_version > SUPPORTED_FDT_VERSION
        || structure < HEADER_SIZE
        || strings < HEADER_SIZE
        || reservations < HEADER_SIZE
        || !reservations.is_multiple_of(8)
        || !structure.is_multiple_of(4)
        || structure_size < 12
        || strings_size == 0
        || structure_end.is_none_or(|end| end > total_size)
        || strings_end.is_none_or(|end| end > total_size)
        || ranges_overlap(
            structure,
            structure_end.unwrap_or(0),
            strings,
            strings_end.unwrap_or(0),
        )
    {
        return Err(Error::InvalidHeader);
    }
    let reservations_end = read_reservation_map_end(source, reservations, total_size)?;
    if ranges_overlap(
        reservations,
        reservations_end,
        structure,
        structure_end.unwrap_or(0),
    ) || ranges_overlap(
        reservations,
        reservations_end,
        strings,
        strings_end.unwrap_or(0),
    ) {
        return Err(Error::InvalidHeader);
    }
    Ok(Header {
        structure,
        strings,
        structure_size,
        strings_size,
    })
}

/// Returns the first byte after the mandatory all-zero reservation terminator.
fn read_reservation_map_end<Source: ReadAt>(
    source: &Source,
    start: u64,
    total_size: u64,
) -> Result<u64, Error<Source::Error>> {
    let mut cursor = start;
    for _ in 0..MAX_RESERVATION_RECORDS {
        let end = cursor.checked_add(16).ok_or(Error::AddressOverflow)?;
        if end > total_size {
            return Err(Error::InvalidHeader);
        }
        let mut entry = [0u8; 16];
        source
            .read_exact_at(cursor, &mut entry)
            .map_err(Error::Source)?;
        let address = be64(&entry, 0).ok_or(Error::InvalidHeader)?;
        let size = be64(&entry, 8).ok_or(Error::InvalidHeader)?;
        cursor = end;
        if address == 0 && size == 0 {
            return Ok(cursor);
        }
    }
    Err(Error::ResourceLimit)
}

fn read_selection<Source: ReadAt>(
    source: &Source,
    header: &Header,
) -> Result<Selection, Error<Source::Error>> {
    let selected = read_default_configuration(source, header)?;
    let mut cursor = Cursor::new(source, header);
    let mut section = Section::Other;
    let mut depth = 0u32;
    let mut current_configuration = false;
    let mut configuration_found = false;
    let mut kernel = None;
    let mut ramdisk = None;
    let mut compatible = None;
    while let Some(event) = cursor.next()? {
        match event {
            Event::Begin(name) => {
                depth = depth.checked_add(1).ok_or(Error::InvalidStructure)?;
                if current_configuration && depth > 3 {
                    return Err(Error::InvalidStructure);
                }
                if depth == 2 {
                    section = if name.equals("configurations") {
                        Section::Configurations
                    } else if name.equals("images") {
                        Section::Images
                    } else {
                        Section::Other
                    };
                }
                if depth == 3 {
                    current_configuration = matches!(section, Section::Configurations)
                        && name.as_bytes() == selected.as_bytes();
                    if current_configuration {
                        if configuration_found {
                            return Err(Error::DuplicateNode);
                        }
                        configuration_found = true;
                    }
                }
            }
            Event::End => {
                if depth == 0 {
                    return Err(Error::InvalidStructure);
                }
                if depth == 3 {
                    current_configuration = false;
                }
                if depth == 2 {
                    section = Section::Other;
                }
                depth -= 1;
            }
            Event::Property(property) => {
                if current_configuration && depth == 3 {
                    match property.name.as_bytes() {
                        b"kernel" => set_once(&mut kernel, property.read_name(source)?)?,
                        b"ramdisk" => set_once(&mut ramdisk, property.read_name(source)?)?,
                        b"hyper,memory-size"
                        | b"hyper,vcpu-count"
                        | b"bootargs"
                        | b"hyper,platform-profile" => return Err(Error::UnsupportedImage),
                        b"compatible" => set_once(
                            &mut compatible,
                            property.string_equals(source, GUEST_IMAGE_COMPATIBLE)?,
                        )?,
                        _ => {}
                    }
                }
            }
        }
    }
    if !configuration_found {
        return Err(Error::MissingConfiguration);
    }
    if compatible != Some(true) {
        return Err(Error::UnsupportedImage);
    }
    Ok(Selection {
        kernel: kernel.ok_or(Error::MissingProperty)?,
        ramdisk,
    })
}

fn read_default_configuration<Source: ReadAt>(
    source: &Source,
    header: &Header,
) -> Result<Name, Error<Source::Error>> {
    let mut cursor = Cursor::new(source, header);
    let mut depth = 0u32;
    let mut configurations = false;
    let mut selected = None;
    while let Some(event) = cursor.next()? {
        match event {
            Event::Begin(name) => {
                depth = depth.checked_add(1).ok_or(Error::InvalidStructure)?;
                if depth == 2 {
                    configurations = name.equals("configurations");
                }
            }
            Event::End => {
                if depth == 0 {
                    return Err(Error::InvalidStructure);
                }
                if depth == 2 {
                    configurations = false;
                }
                depth -= 1;
            }
            Event::Property(property)
                if depth == 2 && configurations && property.name.equals("default") =>
            {
                set_once(&mut selected, property.read_name(source)?)?;
            }
            Event::Property(_) => {}
        }
    }
    selected.ok_or(Error::MissingConfiguration)
}

fn read_image<Source: ReadAt>(
    source: &Source,
    header: &Header,
    selected: Name,
    kernel: bool,
) -> Result<(Payload, Architecture), Error<Source::Error>> {
    let mut cursor = Cursor::new(source, header);
    let mut section = Section::Other;
    let mut depth = 0u32;
    let mut current = false;
    let mut data = None;
    let mut load = None;
    let mut entry = None;
    let mut architecture = None;
    let mut compression = None;
    let mut image_type_valid = None;
    let mut operating_system_valid = None;
    let mut image_found = false;
    while let Some(event) = cursor.next()? {
        match event {
            Event::Begin(name) => {
                depth = depth.checked_add(1).ok_or(Error::InvalidStructure)?;
                if current && depth > 3 {
                    return Err(Error::InvalidStructure);
                }
                if depth == 2 {
                    section = if name.equals("images") {
                        Section::Images
                    } else {
                        Section::Other
                    };
                }
                if depth == 3 {
                    current = matches!(section, Section::Images)
                        && name.as_bytes() == selected.as_bytes();
                    if current {
                        if image_found {
                            return Err(Error::DuplicateNode);
                        }
                        image_found = true;
                    }
                }
            }
            Event::End => {
                if depth == 0 {
                    return Err(Error::InvalidStructure);
                }
                if depth == 3 {
                    current = false;
                }
                if depth == 2 {
                    section = Section::Other;
                }
                depth -= 1;
            }
            Event::Property(property) if current && depth == 3 => match property.name.as_bytes() {
                b"data" => set_once(
                    &mut data,
                    (property.value_offset, u64::from(property.length)),
                )?,
                b"load" => set_once(&mut load, property.read_u64(source)?)?,
                b"entry" => set_once(&mut entry, property.read_u64(source)?)?,
                b"arch" => set_once(&mut architecture, property.read_architecture(source)?)?,
                b"compression" => set_once(&mut compression, property.read_compression(source)?)?,
                b"type" => set_once(
                    &mut image_type_valid,
                    property.string_equals(source, if kernel { "kernel" } else { "ramdisk" })?,
                )?,
                b"os" => set_once(
                    &mut operating_system_valid,
                    property.string_equals(source, "linux")?,
                )?,
                _ => {}
            },
            Event::Property(_) => {}
        }
    }
    if !image_found {
        return Err(Error::MissingProperty);
    }
    let (file_offset, length) = data.ok_or(Error::MissingProperty)?;
    let load_address = if kernel {
        load.ok_or(Error::MissingProperty)?
    } else {
        if load.is_some() || entry.is_some() {
            return Err(Error::UnsupportedImage);
        }
        0 // Relocated from external VM configuration at startup.
    };
    if image_type_valid != Some(true) || operating_system_valid != Some(true) || length == 0 {
        return Err(Error::UnsupportedImage);
    }
    let architecture = architecture.ok_or(Error::MissingProperty)?;
    Ok((
        Payload {
            file_offset,
            length,
            load_address,
            entry_address: entry.unwrap_or(load_address),
            compression: compression.unwrap_or(Compression::None),
        },
        architecture,
    ))
}

fn set_once<T, E>(slot: &mut Option<T>, value: T) -> Result<(), Error<E>> {
    if slot.replace(value).is_some() {
        Err(Error::DuplicateProperty)
    } else {
        Ok(())
    }
}

enum Event {
    Begin(Name),
    End,
    Property(Property),
}

struct Property {
    name: Name,
    value_offset: u64,
    length: u32,
}

impl Property {
    fn read_name<Source: ReadAt>(&self, source: &Source) -> Result<Name, Error<Source::Error>> {
        let name = read_c_string(source, self.value_offset, u64::from(self.length), false)?;
        if name.length.checked_add(1) != usize::try_from(self.length).ok() {
            return Err(Error::InvalidString);
        }
        Ok(name)
    }

    fn read_u64<Source: ReadAt>(&self, source: &Source) -> Result<u64, Error<Source::Error>> {
        if self.length != 8 {
            return Err(Error::InvalidStructure);
        }
        let mut bytes = [0u8; 8];
        source
            .read_exact_at(self.value_offset, &mut bytes)
            .map_err(Error::Source)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_architecture<Source: ReadAt>(
        &self,
        source: &Source,
    ) -> Result<Architecture, Error<Source::Error>> {
        if self.string_equals(source, "arm64")? {
            Ok(Architecture::Aarch64)
        } else if self.string_equals(source, "riscv")? {
            Ok(Architecture::Riscv64)
        } else if self.string_equals(source, "x86_64")? {
            Ok(Architecture::X86_64)
        } else {
            Err(Error::UnsupportedImage)
        }
    }

    fn read_compression<Source: ReadAt>(
        &self,
        source: &Source,
    ) -> Result<Compression, Error<Source::Error>> {
        if self.string_equals(source, "none")? {
            Ok(Compression::None)
        } else if self.string_equals(source, "gzip")? {
            Ok(Compression::Gzip)
        } else {
            Err(Error::UnsupportedImage)
        }
    }

    fn string_equals<Source: ReadAt>(
        &self,
        source: &Source,
        expected: &str,
    ) -> Result<bool, Error<Source::Error>> {
        let value = read_c_string(source, self.value_offset, u64::from(self.length), false)?;
        Ok(
            value.length.checked_add(1) == usize::try_from(self.length).ok()
                && value.as_bytes() == expected.as_bytes(),
        )
    }
}

struct Cursor<'source, Source> {
    source: &'source Source,
    header: &'source Header,
    offset: u64,
    ended: bool,
    depth: u32,
    saw_root: bool,
    tokens: usize,
}

impl<'source, Source: ReadAt> Cursor<'source, Source> {
    const fn new(source: &'source Source, header: &'source Header) -> Self {
        Self {
            source,
            header,
            offset: 0,
            ended: false,
            depth: 0,
            saw_root: false,
            tokens: 0,
        }
    }

    fn next(&mut self) -> Result<Option<Event>, Error<Source::Error>> {
        if self.ended {
            return Ok(None);
        }
        loop {
            self.tokens = self.tokens.checked_add(1).ok_or(Error::ResourceLimit)?;
            if self.tokens > MAX_STRUCTURE_TOKENS {
                return Err(Error::ResourceLimit);
            }
            let token = self.read_u32()?;
            match token {
                FDT_BEGIN_NODE => {
                    let remaining = self
                        .header
                        .structure_size
                        .checked_sub(self.offset)
                        .ok_or(Error::InvalidStructure)?;
                    let name = read_c_string(
                        self.source,
                        self.header.structure + self.offset,
                        remaining,
                        true,
                    )?;
                    if self.depth == 0 {
                        if self.saw_root || name.length != 0 {
                            return Err(Error::InvalidStructure);
                        }
                        self.saw_root = true;
                    } else if name.length == 0 {
                        return Err(Error::InvalidStructure);
                    }
                    self.depth = self.depth.checked_add(1).ok_or(Error::InvalidStructure)?;
                    if self.depth > MAX_STRUCTURE_DEPTH {
                        return Err(Error::ResourceLimit);
                    }
                    self.offset = align4(
                        self.offset
                            .checked_add(
                                u64::try_from(name.length + 1)
                                    .map_err(|_| Error::AddressOverflow)?,
                            )
                            .ok_or(Error::AddressOverflow)?,
                    )?;
                    return Ok(Some(Event::Begin(name)));
                }
                FDT_END_NODE => {
                    self.depth = self.depth.checked_sub(1).ok_or(Error::InvalidStructure)?;
                    return Ok(Some(Event::End));
                }
                FDT_PROP => {
                    if self.depth == 0 {
                        return Err(Error::InvalidStructure);
                    }
                    let length = self.read_u32()?;
                    let name_offset = u64::from(self.read_u32()?);
                    if name_offset >= self.header.strings_size {
                        return Err(Error::InvalidStructure);
                    }
                    let name = read_c_string(
                        self.source,
                        self.header.strings + name_offset,
                        self.header.strings_size - name_offset,
                        true,
                    )?;
                    let value_offset = self
                        .header
                        .structure
                        .checked_add(self.offset)
                        .ok_or(Error::AddressOverflow)?;
                    self.offset = align4(
                        self.offset
                            .checked_add(u64::from(length))
                            .ok_or(Error::AddressOverflow)?,
                    )?;
                    if self.offset > self.header.structure_size {
                        return Err(Error::InvalidStructure);
                    }
                    return Ok(Some(Event::Property(Property {
                        name,
                        value_offset,
                        length,
                    })));
                }
                FDT_NOP => {}
                FDT_END => {
                    if !self.saw_root
                        || self.depth != 0
                        || self.offset != self.header.structure_size
                    {
                        return Err(Error::InvalidStructure);
                    }
                    self.ended = true;
                    return Ok(None);
                }
                _ => return Err(Error::InvalidStructure),
            }
        }
    }

    fn read_u32(&mut self) -> Result<u32, Error<Source::Error>> {
        let end = self.offset.checked_add(4).ok_or(Error::AddressOverflow)?;
        if end > self.header.structure_size {
            return Err(Error::InvalidStructure);
        }
        let mut bytes = [0u8; 4];
        let absolute = self
            .header
            .structure
            .checked_add(self.offset)
            .ok_or(Error::AddressOverflow)?;
        self.source
            .read_exact_at(absolute, &mut bytes)
            .map_err(Error::Source)?;
        self.offset = end;
        Ok(u32::from_be_bytes(bytes))
    }
}

fn read_c_string<Source: ReadAt>(
    source: &Source,
    offset: u64,
    maximum: u64,
    allow_empty: bool,
) -> Result<Name, Error<Source::Error>> {
    let limit = usize::try_from(maximum.min((MAX_NAME_BYTES + 1) as u64))
        .map_err(|_| Error::AddressOverflow)?;
    let mut encoded = [0u8; MAX_NAME_BYTES + 1];
    source
        .read_exact_at(
            offset,
            encoded.get_mut(..limit).ok_or(Error::InvalidString)?,
        )
        .map_err(Error::Source)?;
    let length = encoded
        .get(..limit)
        .and_then(|bytes| bytes.iter().position(|byte| *byte == 0))
        .ok_or(Error::InvalidString)?;
    if length == 0 && !allow_empty {
        return Err(Error::InvalidString);
    }
    let mut name = Name::empty();
    name.bytes
        .get_mut(..length)
        .ok_or(Error::InvalidString)?
        .copy_from_slice(encoded.get(..length).ok_or(Error::InvalidString)?);
    name.length = length;
    Ok(name)
}

fn align4<E>(value: u64) -> Result<u64, Error<E>> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(Error::AddressOverflow)
}

const fn ranges_overlap(
    first_start: u64,
    first_end: u64,
    second_start: u64,
    second_end: u64,
) -> bool {
    first_start < second_end && second_start < first_end
}

fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    let array: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(array))
}

fn be64(bytes: &[u8], offset: usize) -> Option<u64> {
    let array: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    const TOTAL_SIZE: usize = 89;
    const RESERVATIONS: usize = 40;
    const STRUCTURE: usize = 72;
    const STRINGS: usize = 88;

    struct Source([u8; TOTAL_SIZE]);

    impl Source {
        fn valid_fdt() -> Self {
            let mut bytes = [0u8; TOTAL_SIZE];
            put_be32(&mut bytes, 0, FDT_MAGIC);
            put_be32(&mut bytes, 4, TOTAL_SIZE as u32);
            put_be32(&mut bytes, 8, STRUCTURE as u32);
            put_be32(&mut bytes, 12, STRINGS as u32);
            put_be32(&mut bytes, 16, RESERVATIONS as u32);
            put_be32(&mut bytes, 20, SUPPORTED_FDT_VERSION);
            put_be32(&mut bytes, 24, 16);
            put_be32(&mut bytes, 32, 1);
            put_be32(&mut bytes, 36, 16);
            put_be64(&mut bytes, RESERVATIONS, 0x1000);
            put_be64(&mut bytes, RESERVATIONS + 8, 0x2000);
            put_be32(&mut bytes, STRUCTURE, FDT_BEGIN_NODE);
            put_be32(&mut bytes, STRUCTURE + 8, FDT_END_NODE);
            put_be32(&mut bytes, STRUCTURE + 12, FDT_END);
            Self(bytes)
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
    fn accepts_an_aligned_terminated_non_overlapping_reservation_map() {
        assert!(read_header(&Source::valid_fdt()).is_ok());
    }

    #[test]
    fn rejects_a_misaligned_reservation_map() {
        let mut source = Source::valid_fdt();
        put_be32(&mut source.0, 16, (RESERVATIONS + 4) as u32);
        assert!(matches!(read_header(&source), Err(Error::InvalidHeader)));
    }

    #[test]
    fn rejects_a_reservation_map_without_a_zero_tuple() {
        let mut source = Source::valid_fdt();
        put_be64(&mut source.0, RESERVATIONS + 16, 1);
        assert!(matches!(read_header(&source), Err(Error::InvalidHeader)));
    }

    #[test]
    fn rejects_a_reservation_map_which_overlaps_the_structure_block() {
        let mut source = Source::valid_fdt();
        put_be32(&mut source.0, 8, 64);
        assert!(matches!(read_header(&source), Err(Error::InvalidHeader)));
    }

    #[test]
    fn rejects_a_reservation_map_tuple_outside_the_fdt() {
        let mut source = Source::valid_fdt();
        put_be32(&mut source.0, 16, 80);
        assert!(matches!(read_header(&source), Err(Error::InvalidHeader)));
    }

    #[test]
    fn rejects_a_reservation_map_which_exhausts_its_record_budget() {
        const RESERVATION_BYTES: usize = MAX_RESERVATION_RECORDS * 16;
        const STRUCTURE_OFFSET: usize = HEADER_SIZE as usize + RESERVATION_BYTES;
        const STRINGS_OFFSET: usize = STRUCTURE_OFFSET + 16;
        const SIZE: usize = STRINGS_OFFSET + 1;

        let mut bytes = [0u8; SIZE];
        put_be32(&mut bytes, 0, FDT_MAGIC);
        put_be32(&mut bytes, 4, SIZE as u32);
        put_be32(&mut bytes, 8, STRUCTURE_OFFSET as u32);
        put_be32(&mut bytes, 12, STRINGS_OFFSET as u32);
        put_be32(&mut bytes, 16, HEADER_SIZE as u32);
        put_be32(&mut bytes, 20, SUPPORTED_FDT_VERSION);
        put_be32(&mut bytes, 24, 16);
        put_be32(&mut bytes, 32, 1);
        put_be32(&mut bytes, 36, 16);
        for record in 0..MAX_RESERVATION_RECORDS {
            put_be64(&mut bytes, HEADER_SIZE as usize + record * 16, 1);
        }
        let source = SliceSource(&bytes);
        assert!(matches!(read_header(&source), Err(Error::ResourceLimit)));
    }

    #[test]
    fn rejects_structure_tokens_which_exhaust_the_parser_budget() {
        let mut bytes = [0u8; (MAX_STRUCTURE_TOKENS + 1) * 4];
        for token in bytes.chunks_exact_mut(4) {
            token.copy_from_slice(&FDT_NOP.to_be_bytes());
        }
        let source = SliceSource(&bytes);
        let header = Header {
            structure: 0,
            strings: 0,
            structure_size: bytes.len() as u64,
            strings_size: 0,
        };
        assert!(matches!(
            Cursor::new(&source, &header).next(),
            Err(Error::ResourceLimit)
        ));
    }

    #[test]
    fn rejects_structure_nesting_which_exhausts_the_depth_budget() {
        const RECORD_SIZE: usize = 8;
        const RECORDS: usize = MAX_STRUCTURE_DEPTH as usize + 1;
        let mut bytes = [0u8; RECORDS * RECORD_SIZE];
        for (index, record) in bytes.chunks_exact_mut(RECORD_SIZE).enumerate() {
            record[..4].copy_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            if index != 0 {
                record[4] = b'a';
            }
        }
        let source = SliceSource(&bytes);
        let header = Header {
            structure: 0,
            strings: 0,
            structure_size: bytes.len() as u64,
            strings_size: 0,
        };
        let mut cursor = Cursor::new(&source, &header);
        for _ in 0..MAX_STRUCTURE_DEPTH {
            assert!(matches!(cursor.next(), Ok(Some(Event::Begin(_)))));
        }
        assert!(matches!(cursor.next(), Err(Error::ResourceLimit)));
    }

    #[test]
    fn reads_each_bounded_string_with_one_source_operation() {
        let mut bytes = [0u8; MAX_NAME_BYTES + 1];
        bytes[..5].copy_from_slice(b"name\0");
        let source = CountingSource {
            bytes,
            reads: Cell::new(0),
        };
        let name = read_c_string(&source, 0, bytes.len() as u64, false);
        assert!(matches!(name, Ok(name) if name.equals("name")));
        assert_eq!(source.reads.get(), 1);
    }

    struct CountingSource {
        bytes: [u8; MAX_NAME_BYTES + 1],
        reads: Cell<usize>,
    }

    impl ReadAt for CountingSource {
        type Error = ();

        fn length(&self) -> Result<u64, Self::Error> {
            Ok(self.bytes.len() as u64)
        }

        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            self.reads.set(self.reads.get() + 1);
            let start = usize::try_from(offset).map_err(|_| ())?;
            let end = start.checked_add(output.len()).ok_or(())?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
            Ok(())
        }
    }

    struct SliceSource<'bytes>(&'bytes [u8]);

    impl ReadAt for SliceSource<'_> {
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

    fn put_be32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn put_be64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
}
