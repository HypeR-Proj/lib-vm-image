// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Architecture-selected Linux boot plans shared by packers and runtimes.

pub use crate::placement::AddressRange;
use crate::{
    Architecture, ConfiguredImage, PlatformProfile, ReadAt, aarch64_linux, placement, riscv64_linux,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootProtocol {
    Aarch64,
    Riscv64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootPlan {
    protocol: BootProtocol,
    vcpu_count: u32,
    memory: AddressRange,
    kernel: AddressRange,
    initramfs: Option<AddressRange>,
    device_tree: AddressRange,
}
impl BootPlan {
    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        match self.protocol {
            BootProtocol::Aarch64 => Architecture::Aarch64,
            BootProtocol::Riscv64 => Architecture::Riscv64,
        }
    }
    #[must_use]
    pub const fn platform_profile(&self) -> PlatformProfile {
        match self.protocol {
            BootProtocol::Aarch64 => PlatformProfile::Aarch64Reference,
            BootProtocol::Riscv64 => PlatformProfile::Riscv64Reference,
        }
    }
    #[must_use]
    pub const fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }
    #[must_use]
    pub const fn memory_base(&self) -> u64 {
        self.memory.start
    }
    #[must_use]
    pub const fn memory_size(&self) -> u64 {
        self.memory.end - self.memory.start
    }
    #[must_use]
    pub const fn kernel_entry(&self) -> u64 {
        self.kernel.start
    }
    #[must_use]
    pub const fn kernel_load_address(&self) -> u64 {
        self.kernel.start
    }
    #[must_use]
    pub const fn kernel_occupied_range(&self) -> AddressRange {
        self.kernel
    }
    #[must_use]
    pub const fn initramfs(&self) -> Option<AddressRange> {
        self.initramfs
    }
    #[must_use]
    pub const fn device_tree(&self) -> AddressRange {
        self.device_tree
    }
    #[must_use]
    pub const fn bootstrap_arguments(&self) -> [u64; 4] {
        match self.protocol {
            BootProtocol::Aarch64 => [self.device_tree.start, 0, 0, 0],
            BootProtocol::Riscv64 => [0, self.device_tree.start, 0, 0],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    Aarch64(aarch64_linux::ReferenceLayoutError<E>),
    Riscv64(riscv64_linux::ReferenceLayoutError<E>),
    UnsupportedArchitecture,
    UnsupportedPlatformProfile,
}

/// Validates the selected Linux boot protocol and guest-physical payload layout.
///
/// Architecture validators check image headers, RAM bounds and payload/DTB
/// overlap before a runtime allocates guest RAM. The returned plan contains
/// addresses and bootstrap arguments; payload copying and DTB generation remain
/// the caller's responsibility.
pub fn validate_reference<S: ReadAt>(
    source: &S,
    image: ConfiguredImage,
) -> Result<BootPlan, Error<S::Error>> {
    let (protocol, base, kernel, initramfs, device_tree) = match image.architecture {
        Architecture::Aarch64 => {
            let layout =
                aarch64_linux::validate_reference(source, image).map_err(Error::Aarch64)?;
            (
                BootProtocol::Aarch64,
                aarch64_linux::REFERENCE_GUEST_RAM_BASE,
                AddressRange {
                    start: layout.kernel().load_address(),
                    end: layout.kernel().occupied_end(),
                },
                layout.initramfs(),
                layout.device_tree(),
            )
        }
        Architecture::Riscv64 => {
            let layout =
                riscv64_linux::validate_reference(source, image).map_err(Error::Riscv64)?;
            (
                BootProtocol::Riscv64,
                riscv64_linux::REFERENCE_GUEST_RAM_BASE,
                AddressRange {
                    start: layout.kernel().load_address(),
                    end: layout.kernel().occupied_end(),
                },
                layout.initramfs(),
                layout.device_tree(),
            )
        }
        Architecture::X86_64 => return Err(Error::UnsupportedArchitecture),
    };
    // Each architecture validator has already checked this addition and range.
    let end = base
        .checked_add(image.memory_size)
        .ok_or_else(|| match protocol {
            BootProtocol::Aarch64 => {
                Error::Aarch64(aarch64_linux::ReferenceLayoutError::AddressOverflow)
            }
            BootProtocol::Riscv64 => {
                Error::Riscv64(riscv64_linux::ReferenceLayoutError::AddressOverflow)
            }
        })?;
    Ok(BootPlan {
        protocol,
        vcpu_count: image.vcpu_count,
        memory: AddressRange { start: base, end },
        kernel,
        initramfs,
        device_tree,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementError {
    UnsupportedArchitecture,
    UnsupportedPlatformProfile,
    InvalidMemorySize,
    InvalidPayload,
    AddressOverflow,
}

pub fn plan_initramfs_load(
    architecture: Architecture,
    profile: PlatformProfile,
    memory_size: u64,
    length: u64,
) -> Result<u64, PlacementError> {
    let (base, minimum) = match (architecture, profile) {
        (Architecture::Aarch64, PlatformProfile::Aarch64Reference) => (
            aarch64_linux::REFERENCE_GUEST_RAM_BASE,
            aarch64_linux::MINIMUM_REFERENCE_MEMORY_SIZE,
        ),
        (Architecture::Riscv64, PlatformProfile::Riscv64Reference) => (
            riscv64_linux::REFERENCE_GUEST_RAM_BASE,
            riscv64_linux::MINIMUM_REFERENCE_MEMORY_SIZE,
        ),
        (Architecture::X86_64, _) => return Err(PlacementError::UnsupportedArchitecture),
        _ => return Err(PlacementError::UnsupportedPlatformProfile),
    };
    placement::plan_initramfs::<core::convert::Infallible>(base, memory_size, minimum, length)
        .map_err(|error| match error {
            placement::Error::InvalidMemorySize => PlacementError::InvalidMemorySize,
            placement::Error::AddressOverflow => PlacementError::AddressOverflow,
            _ => PlacementError::InvalidPayload,
        })
}

#[must_use]
pub const fn profile_name(profile: PlatformProfile) -> Option<&'static str> {
    match profile {
        PlatformProfile::Aarch64Reference => Some(crate::AARCH64_REFERENCE_PROFILE),
        PlatformProfile::Riscv64Reference => Some(crate::RISCV64_REFERENCE_PROFILE),
        PlatformProfile::X86_64Reference => None,
    }
}
