<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# lib-vm-image

Allocation-free FIT parsing and Linux guest boot metadata.

Consumers implement ReadAt; the parser returns checked payload ranges instead of copying
image bytes. Architecture helpers validate AArch64/RISC-V Linux inputs and construct
guest FDT information.

See the [implementation entry](src/lib.rs) and [component declaration](component.json)
for the public interfaces, build dependencies and delivered artifacts.

## Boundaries

Parsing does not load or execute a VM. Consumers retain source lifetime, stream payloads
into guest memory and reject unsupported compression/architecture combinations
explicitly.

## Build and test

Use this checkout inside the [repo-managed workspace](https://github.com/HypeR-Proj/HypeR).
From this repository directory:

```sh
make
make test
```

An absolute `OUT=/path/to/out` selects a shared output directory. The module
entry delegates to build/system, which prepares the installed SDK and declared
dependencies. Native binaries require HypeR; host module checks cover the tests
selected by component.json. A standalone clone does not contain the workspace’s
other source repositories or Native SDK.

`IoDevices::entropy` describes an explicitly assigned IRQ-free rng200 register
bank. Its guest address and register geometry are fixed, and validation rejects
RAM, device, PCI aperture and reserved interrupt conflicts. The emitted node
contains no host addresses, interrupts or borrowed firmware clock references.
The caller must retain and service the physical assignment; a device-tree entry
alone does not create an entropy source.
