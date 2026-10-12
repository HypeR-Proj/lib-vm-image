// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! RV64 reference-board description, sharing the bounded FDT encoder.

use super::{Builder, Error, hex_node_name};
use crate::linux::BootPlan;
use hyper_abi::*;

pub(super) const ISA: u64 = HYPER_NATIVE_RISCV_ISA_I
    | HYPER_NATIVE_RISCV_ISA_M
    | HYPER_NATIVE_RISCV_ISA_A
    | HYPER_NATIVE_RISCV_ISA_F
    | HYPER_NATIVE_RISCV_ISA_D
    | HYPER_NATIVE_RISCV_ISA_C
    | HYPER_NATIVE_RISCV_ISA_ZICSR
    | HYPER_NATIVE_RISCV_ISA_ZIFENCEI
    | HYPER_NATIVE_RISCV_ISA_SSTC;

pub(super) fn build(
    plan: &BootPlan,
    arguments: &str,
    frequency: u32,
    structure: &mut [u8],
    strings: &mut [u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    const CPU_INTC: u32 = 1;
    const PLIC: u32 = 2;
    let mut builder = Builder::new(structure, strings);
    builder.begin_node("")?;
    builder.property_u32("#address-cells", 2)?;
    builder.property_u32("#size-cells", 2)?;
    builder.property_string("compatible", "hyper,riscv64-reference")?;
    builder.property_string("model", "HypeR RV64 virtual machine")?;

    builder.begin_node("chosen")?;
    builder.property_string("bootargs", arguments)?;
    builder.property_string("stdout-path", "/soc/serial@10000000:115200n8")?;
    if let Some(range) = plan.initramfs() {
        builder.property_u64("linux,initrd-start", range.start())?;
        builder.property_u64("linux,initrd-end", range.end())?;
    }
    builder.end_node()?;
    builder.begin_node("aliases")?;
    builder.property_string("serial0", "/soc/serial@10000000")?;
    builder.end_node()?;

    let mut name = [0; 32];
    builder.begin_node(hex_node_name("memory@", plan.memory_base(), &mut name)?)?;
    builder.property_string("device_type", "memory")?;
    builder.property_u64_pair("reg", plan.memory_base(), plan.memory_size())?;
    builder.end_node()?;

    builder.begin_node("cpus")?;
    builder.property_u32("#address-cells", 1)?;
    builder.property_u32("#size-cells", 0)?;
    builder.property_u32("timebase-frequency", frequency)?;
    builder.begin_node("cpu@0")?;
    builder.property_string("device_type", "cpu")?;
    builder.property_u32("reg", 0)?;
    builder.property_string("status", "okay")?;
    builder.property_string("compatible", "riscv")?;
    builder.property_string("mmu-type", "riscv,sv39")?;
    builder.property_string("riscv,isa", "rv64imafdc_zicsr_zifencei_sstc")?;
    builder.property_string("riscv,isa-base", "rv64i")?;
    builder.property_string_list(
        "riscv,isa-extensions",
        &["i", "m", "a", "f", "d", "c", "zicsr", "zifencei", "sstc"],
    )?;
    builder.begin_node("interrupt-controller")?;
    builder.property_u32("#interrupt-cells", 1)?;
    builder.property_empty("interrupt-controller")?;
    builder.property_string("compatible", "riscv,cpu-intc")?;
    builder.property_u32("phandle", CPU_INTC)?;
    builder.end_node()?;
    builder.end_node()?;
    builder.end_node()?;

    builder.begin_node("soc")?;
    builder.property_u32("#address-cells", 2)?;
    builder.property_u32("#size-cells", 2)?;
    builder.property_string("compatible", "simple-bus")?;
    builder.property_empty("ranges")?;
    builder.begin_node("interrupt-controller@c000000")?;
    builder.property_u32("#address-cells", 0)?;
    builder.property_u32("#interrupt-cells", 1)?;
    builder.property_string("compatible", "sifive,plic-1.0.0")?;
    builder.property_empty("interrupt-controller")?;
    builder.property_u64_pair(
        "reg",
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_PLIC_BASE,
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_PLIC_SIZE,
    )?;
    builder.property_u32("phandle", PLIC)?;
    // Context indexes are positional in the PLIC binding. The absent machine
    // context still occupies slot zero, using a valid CPU interrupt phandle.
    builder.property_cells("interrupts-extended", &[CPU_INTC, u32::MAX, CPU_INTC, 9])?;
    builder.property_u32(
        "riscv,ndev",
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_PLIC_NUM_SOURCES as u32,
    )?;
    builder.end_node()?;

    builder.begin_node("serial@10000000")?;
    builder.property_string("compatible", "ns16550a")?;
    builder.property_u64_pair(
        "reg",
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_UART_BASE,
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_UART_SIZE,
    )?;
    builder.property_u32(
        "clock-frequency",
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_UART_CLOCK_FREQUENCY as u32,
    )?;
    builder.property_u32("current-speed", 115200)?;
    builder.property_u32("reg-io-width", 1)?;
    builder.property_u32("reg-shift", 0)?;
    builder.property_u32("interrupt-parent", PLIC)?;
    builder.property_u32(
        "interrupts",
        HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_UART_INTERRUPT as u32,
    )?;
    builder.end_node()?;
    builder.end_node()?;
    builder.end_node()?;
    builder.finish(output)
}
