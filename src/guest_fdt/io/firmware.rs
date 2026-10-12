// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded, caller-projected device firmware. The caller translates register
//! addresses and phandle references into the guest namespace; none of these
//! descriptive properties authorize a host mapping or device assignment.

use super::{Builder, Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareProperty<'a> {
    pub name: &'a str,
    /// Raw device-tree property bytes, including big-endian cells or string NULs.
    pub value: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareNode<'a> {
    pub name: &'a str,
    pub properties: &'a [FirmwareProperty<'a>],
    pub children: &'a [FirmwareNode<'a>],
}

/// Firmware phandles are disjoint from reference-platform and I/O node handles.
pub const FIRMWARE_PHANDLE_BASE: u32 = 1;
pub const FIRMWARE_PHANDLE_LIMIT: u32 = 0xffff_0000;

pub(super) fn validate(nodes: &[FirmwareNode<'_>]) -> Result<(), Error> {
    let mut budget = Budget {
        nodes: 256,
        bytes: 65536,
        properties: 2048,
        phandles: [0; 256],
        phandle_count: 0,
    };
    validate_nodes(nodes, 0, &mut budget)
}

struct Budget {
    nodes: usize,
    bytes: usize,
    properties: usize,
    phandles: [u32; 256],
    phandle_count: usize,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 127
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b",._+*#?-@".contains(&byte))
}

fn validate_nodes(
    nodes: &[FirmwareNode<'_>],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), Error> {
    if nodes.is_empty() {
        return Ok(());
    }
    if depth >= 8 || nodes.len() > budget.nodes {
        return Err(Error::InvalidInput);
    }
    budget.nodes -= nodes.len();
    for (index, node) in nodes.iter().enumerate() {
        if !valid_name(node.name)
            || node.properties.len() > 32
            || nodes[..index].iter().any(|other| other.name == node.name)
        {
            return Err(Error::InvalidInput);
        }
        budget.bytes = budget
            .bytes
            .checked_sub(node.name.len())
            .ok_or(Error::InvalidInput)?;
        budget.properties = budget
            .properties
            .checked_sub(node.properties.len())
            .ok_or(Error::InvalidInput)?;
        for (index, property) in node.properties.iter().enumerate() {
            if !valid_name(property.name)
                || node.properties[..index]
                    .iter()
                    .any(|other| other.name == property.name)
            {
                return Err(Error::InvalidInput);
            }
            let bytes = property
                .name
                .len()
                .checked_add(property.value.len())
                .ok_or(Error::AddressOverflow)?;
            budget.bytes = budget.bytes.checked_sub(bytes).ok_or(Error::InvalidInput)?;
            if property.name == "linux,phandle"
                && !node
                    .properties
                    .iter()
                    .any(|other| other.name == "phandle" && other.value == property.value)
            {
                return Err(Error::InvalidInput);
            }
            if property.name == "phandle" {
                let bytes: [u8; 4] = property.value.try_into().map_err(|_| Error::InvalidInput)?;
                let value = u32::from_be_bytes(bytes);
                if !(FIRMWARE_PHANDLE_BASE..FIRMWARE_PHANDLE_LIMIT).contains(&value) {
                    return Err(Error::InvalidInput);
                }
                if budget.phandles[..budget.phandle_count].contains(&value) {
                    return Err(Error::InvalidInput);
                }
                budget.phandles[budget.phandle_count] = value;
                budget.phandle_count += 1;
            }
        }
        validate_nodes(node.children, depth + 1, budget)?;
    }
    Ok(())
}

pub(super) fn append(builder: &mut Builder<'_>, nodes: &[FirmwareNode<'_>]) -> Result<(), Error> {
    for node in nodes {
        builder.begin_node(node.name)?;
        for property in node.properties {
            builder.property(property.name, property.value)?;
        }
        append(builder, node.children)?;
        builder.end_node()?;
    }
    Ok(())
}
