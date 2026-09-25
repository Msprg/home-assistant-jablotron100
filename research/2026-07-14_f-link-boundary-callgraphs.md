# F-Link 2.9.2.1509 boundary classes and firmware call graphs

Date: 2026-07-14

Scope: authorized static analysis only; no panel I/O or firmware flashing was performed.

## Evidence and conventions

The analyzed image is `F-Link.unpacked.exe`, SHA-256
`3ae9e67b324a672a589e2b4dd3a4adb4ff07bb90de00d7d47a9f6f85c6bdcd04`.
It is a 32-bit PE with image base `0x00400000`; addresses below are image virtual
addresses (VAs), not file offsets. Ranges are half-open: `[start, end)`. The principal
file-backed code section begins at VA `0x00401000`.

Confidence labels used here:

- **Confirmed**: read directly from Delphi RTTI/VMT metadata, an instruction-level
  call/xref, or the decoded update capture.
- **Strongly inferred**: multiple static observations agree, but a symbol or one
  dispatch edge remains indirect.
- **Speculative**: useful lead that still lacks a discriminating xref or structure
  identification.

The supplied component-map addresses are RTTI anchors. For these Delphi class records,
the dword at the anchor points to class TypeInfo; the TypeInfo names the class and points
to its VMT. In the VMT header, `VMT-64` points to the published-method table, `VMT-52`
holds instance size, and `VMT-48` points at the parent VMT cell. This distinction avoids
treating RTTI or VMT metadata as executable code.

Analysis used the preserved IDC/IDR names, direct PE parsing, `objdump`, string xrefs,
and the decoded `periphery_fw_upgrade.comm.log.htm`. No interactive disassembler was
installed locally. The new dependency-free `f_link_static_tool.py` reproduces the
RTTI-to-VMT-to-published-method correlation.

## Recovered class, VMT, and method relationships

All rows in this table are **confirmed** from RTTI and VMT metadata. A method marked
`stub` points to the shared abstract/unimplemented entry `0x011C9C38`.

| Class | RTTI / TypeInfo | VMT | Size | Direct parent | Published method table and concrete entries |
| --- | --- | --- | ---: | --- | --- |
| `TJAPacker` | `0x00A907F4` / `0x00A907F8` | `0x00A90548` | `0x1C` | `TObject` | `0x00A905AD`: `Create 0x00A90844`, `Destroy 0x00A90A80`, `Read 0x00A90B84`, `ReadBuf 0x00A90CF0`; `Write`, `WriteBuf`, `BeginUpdate`, `EndUpdate` are stubs |
| `TFWFParseThread` | `0x00A9EA64` / `0x00A9EA68` | `0x00A9E810` | `0x9C` | `TInterfacableThread` | `0x00A9E955`: `Create 0x00AA3BEC`, `Destroy 0x00AA3E80`, `Execute 0x00AA3EE4`; `Cancel` is a stub |
| `TPeripheralsUpdate` | `0x00A9E688` / `0x00A9E68C` | `0x00A9E1A8` | `0x3F8` | `TPersistent` | `0x00A9E233`: `Create 0x00AA5700`, `Destroy 0x00AA576C`, `Insert 0x00AA5870`, `GetUpdateItem 0x00AA5260`, `ItemSupported 0x00AA5964`, `AssignVersion 0x00AA53D0`, `AssignVersions 0x00AA5530`, `GetTextTableAbbreviation 0x00AA52FC`; four getters are stubs |
| `TCentral100UpdateFW` | `0x00BD03E0` / `0x00BD03E4` | `0x00BCFFE4` | `0x38` | `TCentral100Plugin` | `0x00BD012C`: `Create 0x00BD09EC`, `Destroy 0x00BD0A70`, `RestoreInternalSetup 0x00BD12D8`, `TryPrepare2WABoot 0x00BF1D70`, `UpdateFirmware 0x00BF3588`, `UpdateFirmwareExecute 0x00BF3708`, `CheckPower 0x00BD08EC`, `UserMessage 0x00BF3878`, `OnlineEvent 0x00BD10A4` |
| `TJA100UpdateFWInfoItem` | `0x00EC35C0` / `0x00EC35C4` | `0x00EC3418` | `0x2C` | `TCollectionItem` | `0x00EC351A`: `Create 0x00EC5DC4`; `GetFWVersion` is a stub |
| `TCentral100CustomMsgPackFile` | `0x00F2DF28` / `0x00F2DF2C` | `0x00F2D8E0` | `0x8C` | `TCentral100File` | `0x00F2D9F6`: `Create 0x00F3C908`, `Destroy 0x00F3D008`, `Clean 0x00F3C7AC`, `CopyStreamTo 0x00F3C7C0`, `DeserializeDOM 0x00F3CE6C`, `FlushBuffers 0x00F3D0E0`, `IsValidStreamSize 0x00F3DF18`, `MergeDOMRead 0x00F5628C`, `MergePendingWrite 0x00F562F4`, `ReadVersionedText 0x00F563BC`, `ReloadBuffers 0x00F56448`, `ResetCIDTable 0x00F56954`, `ResetSIATable 0x00F56958`, `SerializeDOM 0x00F5695C`, `SetInDataSize 0x00F571E8`, `CreateSetupContext 0x00F3CE28`, `GetContext 0x00F3D81C` |
| `TPRFUpdate` | `0x00F8E4F0` / `0x00F8E4F4` | `0x00F8E298` | `0xB8` | `TObject` | `0x00F8E409`: `Create 0x00F94B98`, `Destroy 0x00F94C48`; one overloaded `Create` is a stub |
| `TJA100PeripheralComm` | `0x00F99ED4` / `0x00F99ED8` | `0x00F99D44` | `0x14C` | `TJA100CustomHIDComm` | `0x00F99E10`: `Create 0x00F9A7BC`, overloaded `Create 0x00F9A810` |
| `TPacketParser` | `0x00F9AE70` / `0x00F9AE74` | `0x00F9AC50` | `0x24` | `TObject` | `0x00F9ACB4`: `Create 0x00FA68EC`, `Destroy 0x00FA6924`, `Clean 0x00FA6948`, `Read 0x00FA6E54`, `Run 0x00FA6ED8`, `Terminate 0x00FA70B8` |
| `TJA100HIDComm` | `0x00F99CBC` / `0x00F99CC0` | `0x00F99B9C` | `0x15C` | `TJA100CustomCentralHIDComm` | `0x00F99C68`: `Create 0x00F9A77C` |

The parent chain is itself useful at the transport boundary: **confirmed**
`TJA100PeripheralComm -> TJA100CustomHIDComm`, while
`TJA100HIDComm -> TJA100CustomCentralHIDComm -> TJA100CustomHIDComm`. The common
base publishes `SendPacket` at `0x00F9A3B8`. (`0x00F9A69C`, previously confused with
that method, is the central-HID `SendHB` wrapper.) This supports a shared higher-level
packet path with specialized peripheral and central-HID construction, rather than
separate firmware encoders for every transport.

Constructor constants further distinguish the specializations (**confirmed**):
`TJA100HIDComm.Create` writes word `0x0008` at `+0x13C`; both peripheral constructors
write byte `6` at `+0x75`, word `0x180A` at `+0x13C`, timeout-like dword `500` at
`+0x138`, and byte `1` at `+0x134`.

## Firmware call graph

The following graph separates direct calls from boundary transitions that are selected
through objects or application state:

```text
TFWFParseThread.Create 0x00AA3BEC
  -> TPeripheralsUpdate.Create 0x00AA5700
  -> TJAPacker.Create 0x00A90844

TFWFParseThread.Execute 0x00AA3EE4
  -> internal package pass 0x00AA4098
     -> TJAPacker.Read 0x00A90B84
     -> package helper 0x00A90E2C
     -> TPeripheralsUpdate.Insert 0x00AA5870
     -> GetUpdateItem / ItemSupported / AssignVersion(s)
  => selected TJA100UpdateFWInfoItem records

TCentral100UpdateFW.UpdateFirmware 0x00BF3588
  -> 0x00BF45F0
  -> 0x00BE489C
  => central workflow branches instantiate TPRFUpdate at
     0x00BDE5EB / 0x00BE268F / 0x00BED03B

package-member extraction/validation 0x00F8F458
  <- direct callers 0x00F90AB4 / 0x00F90D5B / 0x00F922F0
  -> firmware stream attached to update/session object

firmware state machine 0x00F92030
  -> stream/block calculation 0x00F91158
  -> textual boot entry builder 0x00F98678
  -> binary boot descriptor builder 0x00F987B4
  -> generic command builder 0x00F94D70
  -> virtual send/transition calls on the communication object
  => TJA100PeripheralComm / common TJA100CustomHIDComm layer
  => HID or YTUN-backed transport selected below the common packet layer

receive side
  TPacketParser.Run 0x00FA6ED8
  -> TPacketParser.Read 0x00FA6E54
  -> routed-packet dispatch (including 0x90 and 0x94/0x96 handlers)
  -> state/ACK fields consumed by 0x00F92030
```

The package-thread calls in the first two blocks are **confirmed**. The transition from
the selected update-info item into the central workflow is **strongly inferred** from
the class roles and surrounding call sites: the remaining calls are indirect and have
not yet been reduced to a single caller chain. The three TPRF construction call sites
and all edges inside the `0x00F92030` state machine are **confirmed**. Association of
the final virtual send with the common HID/YTUN abstraction is **strongly inferred**;
the concrete VMT slot targets still need naming.

`TCentral100UpdateFW.UpdateFirmware` is `[0x00BF3588,0x00BF36BF)` and
`UpdateFirmwareExecute` is `[0x00BF3708,0x00BF3730)`. The latter retries the former
when the returned status is `4`. This is confirmed, but it should not be confused with
per-block RF retries in `TPRFUpdate`.

## Landmark function boundaries

### Package member extraction

- **Confirmed range:** `[0x00F8F458,0x00F901E5)`.
- **Confirmed xref:** the instruction at `0x00F8FD00` loads string
  `"Binary %s extracted to stream"` at `0x00F903F4`.
- **Confirmed callers:** `0x00F90AB4`, `0x00F90D5B`, `0x00F922F0`.
- **Strongly inferred role:** parses and validates the selected JAPKG member/header,
  then copies its firmware content to the update stream. Its size and numerous Delphi
  exception/finally frames explain false function starts inside this range.

This pass found no firmware-decryption path. That agrees with the capture-derived
result: the 512-byte package-member header is removed, the encrypted member payload is
transmitted unchanged, and padding belongs to the transport layer.

### Stream and block calculation

- **Confirmed range:** `[0x00F91158,0x00F9122A)`.
- **Confirmed string xref:** `0x00F911E4` loads the diagnostic at `0x00F91238`.
- **Confirmed callers:** `0x00F91554`, `0x00F915F4`, `0x00F93440`.
- It reads the stream size through session `+0x50`, aligns it to the word-sized global
  block unit at `0x0128A7F8`, converts byte counts into 32-byte frame counts, adds six
  protocol frames, and stores the result at session `+0x4C`.
- The state machine changes the block unit to `0x0100` at `0x00F93434` and immediately
  recalculates it. This is **confirmed** evidence for negotiated/dynamic block sizing.

### ACK/retry/completion state machine

- **Confirmed range:** `[0x00F92030,0x00F9418A)`.
- **Confirmed xref:** `0x00F9399C` loads the summary string at `0x00F94704`,
  `"All blocks written, confirmed=%d, unconfirmed=%d"`.
- This is one large state-dispatch routine keyed in part by session `+0x11`; apparent
  prologues within it are nested Delphi exception handlers.
- It increments `TPRFUpdate.FUnconfirmedBlockCount` at `0x00F93520`, updates repeat
  statistics at `0x00F935A5`, and reads confirmed/unconfirmed counters for completion
  at `0x00F93941` onward. It logs timing and worst-delivery/repeat statistics near the
  final cleanup.
- A compare against ten unconfirmed blocks exists at `0x00F935D3`, but the immediately
  following `test dl,al` sees `AL=0` because of `xor eax,eax`. Therefore the apparent
  abort branch is unreachable in these bytes. The existence of a retry threshold is
  **confirmed**; interpreting this particular compare as the active abort condition
  would be incorrect.

`TPacketParser.Read`, `Run`, and `Terminate` have confirmed ranges
`[0x00FA6E54,0x00FA6ED7)`, `[0x00FA6ED8,0x00FA7040)`, and
`[0x00FA70B8,0x00FA713F)`, respectively. Parser dispatch calls occur at
`0x00F9EC5E`, `0x00F9EC78`, and `0x00F9EC8A`.

## Boot entry and command construction

Two related encodings occur in the state machine:

1. **Confirmed:** `[0x00F98678,0x00F98770)` constructs a boot-entry message. It appends
   four bytes through the pointer stored at `0x01252D54`, then appends the literal
   `AT#BOOT`, and for the central target wraps the result as command `0xF2` through
   `0x00F94D70`. It is called at `0x00F92F57`.
2. **Confirmed:** `[0x00F987B4,0x00F9890D)` creates a ten-byte binary message beginning
   `0x65, 0x08`, followed by an eight-byte descriptor. At `0x00F9337F` the caller forms
   that descriptor from four member-header bytes plus a four-byte value consisting of
   the low three bytes of the 16-byte-aligned payload size and member-header byte
   `+0x20 XOR 1`. The central-target branch again wraps it as command `0xF2`.

The first four-byte value is the capture-visible dynamic boot token with **strongly
inferred** confidence: its use immediately before `AT#BOOT` is unambiguous, but its
producer is not. Only this consumer xref to the pointer at `0x01252D54` was recovered.
The second four-byte value is **confirmed** to be dynamically derived, but calling it
the same token would be speculative; it is part of a distinct eight-byte binary boot
descriptor.

The generic command builder is `[0x00F94D70,0x00F94EA1)`. It has many callers across
the communication subsystem and should be treated as reusable framing code, not as a
firmware-only function.

## Important object and structure offsets

These names come from extended RTTI field metadata and are **confirmed** unless noted.

| Type/context | Offset | Field / observation |
| --- | ---: | --- |
| `TJAPacker` | `+0x04` | `FStream` |
|  | `+0x08` | `FHeaderWritten` |
|  | `+0x09` | `FStreamStart` |
|  | `+0x11` | `FUpdateCount` |
| `TFWFParseThread` | `+0x48/+0x4C` | `FFWFName`, `FFilesCount` |
|  | `+0x54/+0x55/+0x59` | `FCanceled`, `FProgress`, `FProgressMax` |
|  | `+0x5D/+0x61` | `FPack: TJAPacker`, `FInput: TPeripheralsUpdate` |
|  | `+0x65/+0x69/+0x6A` | `FUpdateItems`, `FDoParsePackage`, `FBinaryAssignment` |
|  | `+0x8D` | `FParseResult` |
| `TCentral100UpdateFW` | `+0x18/+0x19` | `DeviceFound`, `FUpdatePos` |
|  | `+0x1D/+0x1E` | `FTerminationSignal`, `FDlgFormHandle` |
|  | `+0x26/+0x2A/+0x2E` | `FPrf`, `FTimeOut`, `FStepCount` |
|  | `+0x32` | `HasNewestFile` |
| `TJA100UpdateFWInfoItem` | `+0x0C` | `FPrfType` |
|  | `+0x0D/+0x11/+0x15` | firmware, hardware, and bootloader version numbers |
|  | `+0x19/+0x1D/+0x21` | `FComment`, `FFileName`, `FVersion` |
| `TPRFUpdate` | `+0x05/+0x09` | peripheral object and `Source` |
|  | `+0x0D/+0x11` | `NewFWVersion`, `Languages` |
|  | `+0x20` | `Descriptor` |
|  | `+0x7A/+0x7B` | `UpdateResult`, `WorstDelivery` |
|  | `+0x8B/+0x9B` | `WorstRepeat`, `TmpWorstDelivery` |
|  | `+0x9F` | `TmpWorstRepeat` |
|  | `+0xA3/+0xA7` | `StartTime`, `TotalTime` |
|  | `+0xAB/+0xAF` | `ConfirmedBlockCount`, `UnconfirmedBlockCount` |
| `TPacketParser` | `+0x04/+0x18` | `fParsedPacket`, `ffRouter` |
|  | `+0x1C` | `fIsPeripheralComm` |
| `TCentral100CustomMsgPackFile` | `+0x40/+0x44` | output/input data sizes |
|  | `+0x48/+0x4C/+0x50` | schema, read DOM, pending DOM |
|  | `+0x54/+0x6C` | read/pending locks |
|  | `+0x84` | configuration name |

The firmware state-machine session object itself is not yet named. Its observed
`+0x50` stream, `+0x54` `TPRFUpdate`, `+0x5C` attempt/state counter, and `+0x11`
dispatch state are therefore **strongly inferred structure fields**, not RTTI names.

## Package selection and state observations

- `TFWFParseThread.Create` constructs both the packer and update catalogue and sets
  initial parse result `0x103`. `Execute` repeatedly calls `TJAPacker.Read`, package
  helper `0x00A90E2C`, and catalogue insertion/selection methods. **Confirmed.**
- `TPeripheralsUpdate.ItemSupported`, `AssignVersion`, and `AssignVersions` form the
  reusable applicability/version boundary. Their exact comparison field semantics are
  not all named yet. **Strongly inferred.**
- `TJA100UpdateFWInfoItem` stores PRF type and firmware/hardware/bootloader version
  values alongside the selected member filename. **Confirmed.**
- The decoded firmware-update log contains ACK, retry, timeout, confirmed/unconfirmed,
  and block events matching the static counters and state transitions. This pass used
  aggregate/event evidence only and did not reproduce private capture values.
- Routed receive handling includes packet-header cases `0x90`, `0x94`, and `0x96` near
  `0x00F9DAD4`/`0x00F9DB24`. Mapping each case to a named ACK type is still
  **speculative**.

## Unresolved branches and next exact targets

1. Trace writes to the allocation referenced by pointer `0x01252D54`, starting from
   its initialization/owner rather than searching for its bytes. This is the shortest
   route to the dynamic four-byte `AT#BOOT` token's provenance.
2. Name the VMT slots invoked by the firmware state machine, especially calls through
   offsets `+0x30`, `+0x3C`, `+0x40`, and `+0x68`, then resolve each implementation in
   `TJA100PeripheralComm`, `TJA100CustomHIDComm`, and the YTUN sibling. This will close
   the last indirect packet-transmission edges.
3. Reduce the large central workflow call sites at `0x00BDE5EB`, `0x00BE268F`, and
   `0x00BED03B` to named methods and connect the selected `TJA100UpdateFWInfoItem`
   directly to the chosen `TPRFUpdate` constructor.
4. Fully type the selected JAPKG member header in `[0x00F8F458,0x00F901E5)`, focusing
   on the four bytes copied from `+0x04..+0x07`, flag byte `+0x20`, payload length, and
   validation failures. Do not pursue decryption.
5. Split `[0x00F92030,0x00F9418A)` into named state cases using the jump tables at its
   entry, then correlate each case with sanitized capture event classes. In particular,
   identify the live retry-abort condition instead of assuming the unreachable compare
   at `0x00F935D3` supplies it.

## Verification performed

- Recomputed the executable SHA-256 and PE layout.
- Ran `f_link_static_tool.py` against all ten priority RTTI anchors and their parents;
  every class name, VMT, instance size, and published method above was reproduced.
- Checked landmark prologues, epilogues, direct callers, and string immediates with
  `objdump`.
- Decoded the supplied communication log with the existing log tool and checked only
  non-sensitive event categories against the static state machine.
- Added focused synthetic-PE and IDC-range tests for the reusable correlation tool.

Not validated: live device behavior, firmware acceptance, cryptographic meaning of
either dynamic four-byte value, the producer of the `AT#BOOT` token, concrete HID/YTUN
VMT targets for every virtual send, or a complete semantic name for every state in the
large firmware routine.
