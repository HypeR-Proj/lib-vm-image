// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Admitted BCM2712 SD-card dependency graph, using upstream DT bindings.
//! Window addresses are guest register addresses, including sub-page offsets.

use super::{
    Aarch64LinuxBoot, Builder, Error, IoDevices, MmioDevice, PAGE_SIZE, hex_node_name, overlaps,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioWindow {
    pub base: u64,
    pub size: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdhciRevision {
    C0,
    D0,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdhciDevice {
    pub host: MmioDevice,
    pub config: MmioWindow,
    pub main_pinctrl: MmioWindow,
    pub aon_pinctrl: MmioWindow,
    pub aon_gpio: MmioWindow,
    pub revision: SdhciRevision,
    pub clock_hz: u64,
    pub gpio_widths: [u32; 2],
}
// Reference-platform and I/O phandles occupy 0xffff_0000 and above;
// lower values remain available to projected firmware.
const CLOCK: u32 = 0xffff_0100;
const MAIN_PINS: u32 = 0xffff_0101;
const AON_PINS: u32 = 0xffff_0102;
const GPIO: u32 = 0xffff_0103;
const IO_VOLTAGE: u32 = 0xffff_0104;
const CARD_POWER: u32 = 0xffff_0105;

impl SdhciDevice {
    pub(super) fn validate(
        self,
        io: IoDevices<'_>,
        boot: Aarch64LinuxBoot<'_>,
    ) -> Result<(), Error> {
        let (main_size, aon_size, widths) = match self.revision {
            SdhciRevision::C0 => (0x30, 0x20, [17, 6]),
            SdhciRevision::D0 => (0x20, 0x1c, [15, 6]),
        };
        if io.virtio.is_some()
            || io.dma_ranges.is_empty()
            || self.host.size != 0x260
            || self.config.size != 0x200
            || self.main_pinctrl.size != main_size
            || self.aon_pinctrl.size != aon_size
            || self.aon_gpio.size != 0x40
            || self.gpio_widths != widths
            || self.clock_hz == 0
            || self.clock_hz > u64::from(u32::MAX)
        {
            return Err(Error::InvalidInput);
        }
        let own_end = boot
            .memory_base
            .checked_add(boot.memory_size)
            .ok_or(Error::AddressOverflow)?;
        let windows = [
            MmioWindow {
                base: self.host.base,
                size: self.host.size,
            },
            self.config,
            self.main_pinctrl,
            self.aon_pinctrl,
            self.aon_gpio,
        ];
        for (index, window) in windows.iter().enumerate() {
            let limit = window
                .base
                .checked_add(window.size)
                .ok_or(Error::AddressOverflow)?;
            if window.base < 0x0b00_0000
                || limit > 0x0c00_0000
                || window.base / PAGE_SIZE != (limit - 1) / PAGE_SIZE
                || overlaps(window.base, limit, boot.memory_base, own_end)
                || io.shared_memory.is_some_and(|memory| {
                    memory
                        .base
                        .checked_add(memory.size)
                        .is_none_or(|end| overlaps(window.base, limit, memory.base, end))
                })
                || io.clients.iter().any(|client| {
                    client
                        .shared_memory
                        .base
                        .checked_add(client.shared_memory.size)
                        .is_none_or(|end| {
                            overlaps(window.base, limit, client.shared_memory.base, end)
                        })
                })
                || windows[..index]
                    .iter()
                    .any(|old| overlaps(window.base, limit, old.base, old.base + old.size))
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }

    pub(super) fn append(self, b: &mut Builder<'_>) -> Result<(), Error> {
        let (main_compatible, aon_compatible) = match self.revision {
            SdhciRevision::C0 => ("brcm,bcm2712c0-pinctrl", "brcm,bcm2712c0-aon-pinctrl"),
            SdhciRevision::D0 => ("brcm,bcm2712d0-pinctrl", "brcm,bcm2712d0-aon-pinctrl"),
        };
        b.begin_node("sd-clock")?;
        b.property_string("compatible", "fixed-clock")?;
        b.property_u32("#clock-cells", 0)?;
        b.property_u32("clock-frequency", self.clock_hz as u32)?;
        b.property_u32("phandle", CLOCK)?;
        b.end_node()?;
        window_node(b, "pinctrl@", main_compatible, self.main_pinctrl)?;
        b.begin_node("emmc-sd-default-state")?;
        b.property_u32("phandle", MAIN_PINS)?;
        b.property_string_list(
            "pins",
            &[
                "emmc_cmd",
                "emmc_dat0",
                "emmc_dat1",
                "emmc_dat2",
                "emmc_dat3",
            ],
        )?;
        b.property_empty("bias-pull-up")?;
        b.end_node()?;
        b.end_node()?;
        window_node(b, "pinctrl@", aon_compatible, self.aon_pinctrl)?;
        b.begin_node("emmc-aon-cd-default-state")?;
        b.property_u32("phandle", AON_PINS)?;
        b.property_string("function", "sd_card_g")?;
        b.property_string("pins", "aon_gpio5")?;
        b.property_empty("bias-pull-up")?;
        b.end_node()?;
        b.end_node()?;
        let mut name = [0; 64];
        b.begin_node(hex_node_name("gpio@", self.aon_gpio.base, &mut name)?)?;
        b.property_string_list("compatible", &["brcm,bcm7445-gpio", "brcm,brcmstb-gpio"])?;
        b.property_u64_pair("reg", self.aon_gpio.base, self.aon_gpio.size)?;
        b.property_empty("gpio-controller")?;
        b.property_u32("#gpio-cells", 2)?;
        b.property_cells("brcm,gpio-bank-widths", &self.gpio_widths)?;
        b.property_u32("phandle", GPIO)?;
        // Firmware owns the AON interrupt path. No GPIO IRQ is synthesized.
        b.end_node()?;
        b.begin_node("sd-io-voltage")?;
        b.property_string("compatible", "regulator-gpio")?;
        b.property_string("regulator-name", "vdd-sd-io")?;
        b.property_u32("regulator-min-microvolt", 1_800_000)?;
        b.property_u32("regulator-max-microvolt", 3_300_000)?;
        b.property_empty("regulator-boot-on")?;
        b.property_empty("regulator-always-on")?;
        b.property_u32("regulator-settling-time-us", 5000)?;
        b.property_cells("gpios", &[GPIO, 3, 0])?;
        b.property_cells("states", &[1_800_000, 1, 3_300_000, 0])?;
        b.property_u32("phandle", IO_VOLTAGE)?;
        b.end_node()?;
        b.begin_node("sd-card-power")?;
        b.property_string("compatible", "regulator-fixed")?;
        b.property_string("regulator-name", "vcc-sd")?;
        b.property_u32("regulator-min-microvolt", 3_300_000)?;
        b.property_u32("regulator-max-microvolt", 3_300_000)?;
        b.property_empty("regulator-boot-on")?;
        b.property_empty("enable-active-high")?;
        b.property_cells("gpios", &[GPIO, 4, 0])?;
        b.property_u32("phandle", CARD_POWER)?;
        b.end_node()?;
        b.begin_node(hex_node_name("mmc@", self.host.base, &mut name)?)?;
        b.property_string_list("compatible", &["brcm,bcm2712-sdhci", "brcm,sdhci-brcmstb"])?;
        let mut registers = [0; 32];
        for (chunk, value) in registers.chunks_exact_mut(8).zip([
            self.host.base,
            self.host.size,
            self.config.base,
            self.config.size,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        b.property("reg", &registers)?;
        b.property_string_list("reg-names", &["host", "cfg"])?;
        b.property_cells("interrupts", &[0, self.host.irq - 32, 4])?;
        b.property_cells("clocks", &[CLOCK])?;
        b.property_string("clock-names", "sw_sdio")?;
        b.property_string("pinctrl-names", "default")?;
        b.property_cells("pinctrl-0", &[MAIN_PINS, AON_PINS])?;
        b.property_u32("vqmmc-supply", IO_VOLTAGE)?;
        b.property_u32("vmmc-supply", CARD_POWER)?;
        b.property_cells("cd-gpios", &[GPIO, 5, 1])?;
        b.property_u32("bus-width", 4)?;
        for property in [
            "mmc-ddr-3_3v",
            "sd-uhs-sdr50",
            "sd-uhs-ddr50",
            "sd-uhs-sdr104",
        ] {
            b.property_empty(property)?;
        }
        b.end_node()
    }
}
fn window_node(
    b: &mut Builder<'_>,
    prefix: &str,
    compatible: &str,
    window: MmioWindow,
) -> Result<(), Error> {
    let mut name = [0; 64];
    b.begin_node(hex_node_name(prefix, window.base, &mut name)?)?;
    b.property_string("compatible", compatible)?;
    b.property_u64_pair("reg", window.base, window.size)
}
