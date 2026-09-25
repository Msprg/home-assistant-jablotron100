# F-Link 2.9.2.1509 communication protocol boundaries

Date: 2026-07-14

Scope: authorized static analysis of the preserved F-Link executable and existing,
sanitized research artifacts. No live panel I/O, configuration change, or firmware
operation was performed.

## Result

This pass recovered two distinct communication layers that should not be collapsed
into one codec:

1. Direct HID uses application frames of `type || one-byte length || payload`, packed
   into 64-byte transfers. `TJA100CustomHIDComm.SendPacket` delegates those bytes to
   the physical HID layer.
2. Streamed communication adds an `H`/`I`/`J` fragment layer (`0x48` initial, `0x49`
   continuation, `0x4A` terminal). `TPacketParser` consumes the initial fragment with
   a count at byte 2 and application data at byte 4, then continuation and terminal
   fragments whose data begins at byte 3. It reconstructs the same routed application
   messages and handles the special length marker `0xFA`.

The transport abstraction is also concrete: direct central HID and peripheral HID
share `TJA100CustomHIDComm`; the streamed hierarchy presents one `SendPacket` VMT slot
at `+0xAC`, implemented by file, HID, and YTUN classes. Heartbeat and reconnect policy
sits above those physical writes.

## Evidence, addresses, and confidence

The analyzed `F-Link.unpacked.exe` has SHA-256
`3ae9e67b324a672a589e2b4dd3a4adb4ff07bb90de00d7d47a9f6f85c6bdcd04`.
It is a PE32 image with image base `0x00400000`. All addresses are image virtual
addresses (VAs); ranges are half-open `[start, end)`.

Confidence labels:

- **Confirmed**: Delphi RTTI/VMT metadata, instructions, direct xrefs, or independently
  established frame behavior agree.
- **Strongly inferred**: the code operation is clear but a domain name or one indirect
  caller edge remains unresolved.
- **Speculative**: a useful lead without enough discriminating evidence.

Delphi uses two related RTTI address conventions here. Component-map entries normally
identify a pointer cell whose dword points to class TypeInfo. A TypeInfo parent-class
field instead points directly to the parent's TypeInfo. The updated
`f_link_static_tool.py` accepts both and follows TypeInfo to the VMT; neither address
is executable code.

Analysis used the executable, preserved IDC/IDR metadata, `objdump`, class and record
RTTI, VMT comparisons, and existing protocol documentation. No interactive
disassembler was available.

## Direct HID hierarchy and VMTs

The following relationships and published names are **confirmed**.

| Class | RTTI cell or TypeInfo | VMT | Size | Direct parent | Communication entries |
| --- | --- | --- | ---: | --- | --- |
| `TJAHIDComm` | `0x00F9949C` | `0x00F99344` | `0x148` | lower HID class | 50 slots; `IsPresent` is abstract |
| `TJA100CustomHIDComm` | TypeInfo `0x00F99790` | `0x00F995A4` | `0x14C` | `TJAHIDComm` | adds `+0xC8 = SendPacket 0x00F9A3B8` |
| `TJA100CustomCentralHIDComm` | TypeInfo `0x00F99A90` | `0x00F998C0` | `0x158` | `TJA100CustomHIDComm` | `SendHB 0x00F9A69C`; `TrySendPing 0x00F9A6BC` |
| `TJA100HIDComm` | `0x00F99CBC` | `0x00F99B9C` | `0x15C` | `TJA100CustomCentralHIDComm` | `Create 0x00F9A77C` |
| `TJA100PeripheralComm` | `0x00F99ED4` | `0x00F99D44` | `0x14C` | `TJA100CustomHIDComm` | constructors `0x00F9A7BC`, `0x00F9A810`; overrides `+0xB8`, `+0xBC` |

Important VMT differences:

- `TJA100CustomHIDComm` extends its parent from 50 to 51 slots. Its new `+0xC8`
  slot is the published `SendPacket` method. It overrides physical-operation slots at
  `+0x78`, `+0xA0`, `+0xA4`, `+0xA8`, `+0xB0`, `+0xB8`, and `+0xC4`.
- `TJA100CustomCentralHIDComm` overrides `+0x38`, `+0xA0`, and `+0xA8`, but inherits
  `SendPacket`.
- `TJA100HIDComm` only overrides construction at `+0x38`.
- `TJA100PeripheralComm` overrides construction plus `+0xB8` and `+0xBC`; the latter
  is the retry/logging wrapper at `0x00F9A874`.

Correction to the preceding boundary report: `TJA100CustomHIDComm.SendPacket` is
`0x00F9A3B8`, not `0x00F9A698`. The nearby `0x00F9A69C` is the published `SendHB`
wrapper. The earlier report has been corrected in place.

## Direct HID send and liveness call graph

```text
application packet bytes
  -> TJA100CustomHIDComm.SendPacket [0x00F9A3B8, 0x00F9A3CE)
     -> virtual +0x78
        -> TJA100CustomHIDComm.+0x78 0x00F9A3D0
           -> lower HID implementation 0x0071FBCC

peripheral physical write
  -> TJA100PeripheralComm.+0xBC [0x00F9A874, 0x00F9A927)
     -> overlapped HID operation [0x00F9A0A0, 0x00F9A21D)
     -> log "Peripheral comm write error %s" for each failed attempt
     -> sleep 100 ms between attempts, at most 30 attempts

central heartbeat
  -> TJA100CustomCentralHIDComm.SendHB [0x00F9A69C, 0x00F9A6AA)
     -> inherited virtual +0xC8 SendPacket with static bytes 52 01 02

central ping scheduler
  -> TrySendPing [0x00F9A6BC, 0x00F9A753)
     -> compare current tick with FLastPingTick and FPingDelay
     -> log "Ping timeout" after more than 3 * FPingDelay
     -> build/get ping packet through 0x00F97730
     -> inherited virtual +0xC8 SendPacket
     -> update FLastPingTick
```

All addresses, virtual offsets, loop limits, delay values, and the heartbeat bytes are
**confirmed**. The Windows operation at `0x00F9A0A0` uses a 65-byte buffer, overlapped
completion, object timeout `+0x138`, and retry count `+0x13E`; calling it a HID report
write is **strongly inferred** from its caller and error path because the imported API
names were not fully assigned in the preserved database.

The inherited `+0xA0` routine `[0x00F9A4EC, 0x00F9A5DF)` makes the report boundary
explicit. It zeroes a 65-byte local buffer. For input of at most 64 bytes it copies the
input beginning at buffer byte 1, leaving byte 0 as the report-ID position, then calls
virtual `+0xBC`. For longer input it repeatedly uses helper
`[0x00F98E98, 0x00F99049)` to populate the same buffer and calls `+0xBC`, stopping
after the helper emits `0x4A`. The common `+0xBC` target is `0x00F9A0A0`; the
peripheral specialization replaces it with the retry wrapper at `0x00F9A874`.

The helper recovers the complete outer HID fragmentation format (**confirmed**). Let
`L` be the total application-frame length, including its type and length bytes:

| Physical report bytes | Value / meaning |
| --- | --- |
| byte 0 | zero/report-ID position |
| byte 1 | `0x48` (`H`) initial, `0x49` (`I`) continuation, or `0x4A` (`J`) terminal |
| byte 2 | `0x3E` for `H`/`I`; remaining data length (`<= 0x3E`) for `J` |
| `H` byte 3 | fragment count `(L + 62) div 62` |
| `H` byte 4 | application type |
| `H` byte 5 | application length, capped at `0xFA` |
| `H` bytes 6..64 | first 59 application-payload bytes |
| `I`/`J` bytes 3..64 | next 62 or final remaining application bytes |

The first fragment therefore carries 61 application bytes (type, length, and 59
payload bytes); each later fragment carries at most 62. The count expression is also
`1 + ceil((L - 61) / 62)` for the long inputs that enter this helper.

The central constructor initializes `FPingDelay` to 5000 and a lower timeout field to
100. The concrete central HID constructor selects PID `0x0008`. Peripheral constructors
select PID `0x180A`, set timeout 500, and initialize their specialization flags. These
constants are **confirmed**, but they are product/interface selectors rather than
application protocol opcodes.

`[0x00F9A4C8, 0x00F9A4EC)` normalizes byte 2 of a received buffer: when bit `0x40` is
set it records an error-state bit and subtracts two; otherwise it masks the byte with
`0x3F`. The byte operations are **confirmed**; their precise HID status semantics are
**speculative**.

## Streamed transport hierarchy

The streamed family derives from the file-oriented communication object and exposes a
single higher-level transport slot. The table is **confirmed** from RTTI and VMTs.

| Class | RTTI | VMT | Size | Relevant VMT entries |
| --- | --- | --- | ---: | --- |
| `TJA100FileComm` | `0x00F9B368` | `0x00F9AF50` | `0x334` | 41 slots; adds `+0x9C`, `+0xA0` |
| `TJA100StreamedComm` | `0x00F9BB6C` | `0x00F9B914` | `0x34C` | extends to 44 slots; `+0xA4` and `+0xAC` abstract; `+0xA8 = liveness routine 0x00FA6524` |
| `TJA100StreamedFileComm` | `0x00F9BF0C` | `0x00F9BD04` | `0x358` | `+0xAC = SendPacket 0x00FA5E04` |
| `TJA100BufferedComm` | `0x00F9C1F0` | `0x00F9C040` | `0x354` | buffering layer; overrides `+0xA0`, `+0xA4` |
| `TJA100CustomStreamedHIDComm` | `0x00F9C494` | `0x00F9C348` | `0x358` | `+0xAC = SendPacket 0x00FA6158` |
| `TJA100StreamedHIDComm` | `0x00F9C6DC` | `0x00F9C5A0` | `0x35C` | constructs a `TJA100HIDComm` attachment |
| `TJA100StreamedYTUNComm` | `0x00F9CA38` | `0x00F9C854` | `0x35C` | `+0xAC = SendPacket 0x00FA62E0`; byte counters at `0x00FA629C`, `0x00FA62B0` |

```text
streamed application packet
  -> virtual TJA100StreamedComm.+0xAC
     |-> file: TJA100StreamedFileComm.SendPacket 0x00FA5E04
     |   -> attached FJA100Comm object at +0x84 -> its virtual +0xC8
     |-> HID: TJA100CustomStreamedHIDComm.SendPacket 0x00FA6158
     |   -> attached TJA100HIDComm at +0x84 -> virtual +0xC8
     |   -> update LastHBTick
     `-> YTUN: TJA100StreamedYTUNComm.SendPacket 0x00FA62E0
         -> YTUN object at +0x84 -> 0x00EAAE2C
         -> update LastHBTick
```

This establishes `+0xAC` as the common streamed send boundary and `+0x84` as the
physical attachment/object boundary (**confirmed**). It does not establish identical
wire framing below HID and YTUN; transport-specific code remains below this point.

## Application framing and `TPacketParser`

### Short direct frames

Existing code and the recovered parser helpers agree on the short application format:

```text
offset  size  meaning
0       1     application packet type
1       1     payload length
2       N     payload
```

Thus total application-frame length is `payload_length + 2`. Multiple frames may be
packed into one 64-byte HID transfer. Types `0x90`, `0x94`, and `0x96` are explicitly
recognized by routing helpers near `0x00F9DAD4` and `0x00F9DB24`; their established
uses are device information and diagnostic traffic. This format is **confirmed** for
ordinary short frames. A transfer boundary is not necessarily an application-frame
boundary.

### Parser object and reassembly record

`TPacketParser` RTTI `0x00F9AE70`, VMT `0x00F9AC50`, has size `0x24` and fields:

| Object offset | RTTI name | Role |
| ---: | --- | --- |
| `+0x04` | `fParsedPacket` | embedded reassembly record |
| `+0x18` | `ffRouter` | effective/fallback router |
| `+0x1C` | `fIsPeripheralComm` | transport/context flag |

The embedded record has its own RTTI at `0x00F9AB44`, size `0x14`:

| Record offset | RTTI name |
| ---: | --- |
| `+0x00` | `fRouter` |
| `+0x04` | `fParentRouter` |
| `+0x08` | `fParsedPacketsRemain` |
| `+0x0C` | `fParsedPacketsCount` |
| `+0x10` | `fPartialPacket` |

All names and offsets are **confirmed**.

### Fragment state machine

```text
initial fragment (`H`, 0x48)
  TPacketParser.Run [0x00FA6ED8, 0x00FA7040)
    fragment_count = input[2]
    remaining = fragment_count - 1
    partial_packet += input[4:]
    derive router; use parent router if derivation is negative

continuation fragment (`I`, 0x49)
  TPacketParser.Read [0x00FA6E54, 0x00FA6ED7)
    require remaining > 0
    remaining -= 1
    partial_packet += input[3:]

terminal fragment (`J`, 0x4A)
  TPacketParser.Terminate [0x00FA70B8, 0x00FA713F)
    partial_packet += input[3:]
    remaining -= 1
    accept only when remaining reaches zero; otherwise clean/reject

completion/validation [0x00FA6AF0, 0x00FA6D4F)
  reject reconstructed data shorter than 62 bytes
  normal: len(packet) - 2 must equal packet[1]
  extended: packet[1] == 0xFA uses fragment-count-derived sizing
  special 0x90 case: packet[4] == 0xFA promotes packet[1] to 0xFA
```

These byte positions, counters, opcodes, and validation rules are **confirmed**.

The global receive switch maps `0x48 -> 0x00F9EC5E -> Run`,
`0x49 -> 0x00F9EC78 -> Read`, and `0x4A -> 0x00F9EC8A -> Terminate`. This was checked
directly through its selector table at `0x00F9DE56` and target table at `0x00F9DF3F`.

Router extraction is **confirmed**:

- type `0x90`: router is application byte 2; content begins at byte 4, with the
  `0xFA` extended-length case;
- types `0x94` and `0x96`: router is application byte 2; content begins at byte 5;
  `0x96` supports the `0xFA` length marker.

This parser is principally the streamed/fragmented routing layer. It is not evidence
that every ordinary direct-HID frame needs the outer fragment envelope.

## Heartbeat, timeout, and reconnect policy

The recovered lifecycle boundary is split across three classes:

- `TJA100CustomCentralHIDComm` sends heartbeat `52 01 02` and tracks
  `FLastPingTick +0x148` / `FPingDelay +0x14C`.
- `TJA100StreamedComm` tracks `LastHBTick +0x334`, `LastPing +0x338`,
  `CanSendHB +0x33C`, `HBDelay +0x33D`, and published `PingCnt +0x341`.
  Published `ResetLastPing [0x00FA6518, 0x00FA6521)` clears `LastPing`; the
  separate virtual liveness routine at VMT `+0xA8` is
  `[0x00FA6524, 0x00FA670D)`.
- `TCentral100ReconnectCU` (RTTI `0x00BA7CC0`, VMT `0x00BA7900`) publishes
  `Init 0x00BA82D8`, `StopPing 0x00BA8534`, `SendDebug 0x00BA851C`,
  `SendPacket 0x00BA8528`, `WaitForConnect 0x00BA8E0C`, and
  `WaitForDisconnect 0x00BA8FBC`.

The `+0xA8` liveness routine compares elapsed time with `HBDelay`, logs `"HB timeout"`
beyond a multiple of that delay, and has escalation thresholds at 7 and 15 before
resetting state and requesting higher-level action. The comparisons and state writes are
**confirmed**; the exact user-visible meaning of each threshold is **strongly
inferred** pending reduction of its callbacks.

`TJA100USBDeviceConnector` (RTTI `0x00B55CD0`, VMT `0x00B55AAC`) stores VID/PID,
talker initialization state, usable HID instances, disconnected state, and the device
list. Its published `TryExecuteTalker` at `0x00B57E84` is the exact next target for
device disappearance and reconnect race handling.

## Implications for a stable implementation

The present direct client correctly constructs short frames as
`type || len(payload) || payload`, and its known application packet IDs align with the
static parser. The most valuable robustness change is a persistent receive codec rather
than more opcode guessing:

1. Append every read to a persistent byte buffer.
2. Wait for two bytes before reading the length.
3. Emit a frame only when `length + 2` bytes are available.
4. Preserve an incomplete tail across HID reads instead of treating it as malformed.
5. Treat trailing zeroes as report padding only when no incomplete frame is pending.
6. Bound buffered size and add an explicit, logged resynchronization policy for an
   implausible length; do not silently discard the whole read.
7. Keep streamed `H`/`I`/`J` reassembly and `0xFA` extended lengths in a separate
   codec selected by transport/session context.

These are design recommendations, not claims that the current client has observed
every failure mode. No runtime implementation was changed in this pass.

Request/response coordination should likewise be keyed by application type plus the
known route/context, with independent deadlines for a transaction and the liveness
heartbeat. F-Link's code shows that physical-write retries, application ACK handling,
heartbeat timeout, and reconnect orchestration are separate layers. A stable client
should not let one shared retry counter stand in for all four.

## Unresolved branches and exact next targets

1. Trace the zero-remaining `J` path from `TPacketParser.Terminate` into validation at
   `[0x00FA6AF0, 0x00FA6D4F)` and then the completed-packet callback. Recover every
   reject/resynchronization path around the enclosing dispatcher at `0x00F9DBA8`.
2. Identify and name the imported operations called by `[0x00F99F0C, ... )` and
   `[0x00F9A0A0, 0x00F9A21E)`, then separate physical HID read, write, cancellation,
   timeout, and completion statuses without relying on neighboring strings.
3. Trace the completed `TPacketParser` record into request waiters. Prioritize packet
   types `0x40`, `0x51`, `0x52`, `0x55`, `0x80`, `0x90`, `0x94`, `0x96`, and `0xD8`
   because they cover session setup, commands, state, device information, and
   diagnostics already used by the integration.
4. Reduce `TJA100USBDeviceConnector.TryExecuteTalker 0x00B57E84` together with
   `TCentral100ReconnectCU.WaitForConnect/WaitForDisconnect`. Record the exact
   cancellation and backoff transitions needed to avoid reconnect races.
5. Split the liveness routine `[0x00FA6524, 0x00FA670D)` into its
   threshold/callback cases and determine whether `LastPing`, `PingCnt`, or both are
   attempt counters in each mode.
6. Follow `TJA100StreamedYTUNComm.SendPacket 0x00FA62E0` into `0x00EAAE2C` and its
   receive counterpart to determine whether YTUN carries identical application frames
   or adds a transport envelope below the common slot.

The large switch near `0x0104F000` was deliberately not labeled as a protocol opcode
dispatcher: current evidence indicates domain/peripheral model mapping, and string
proximity alone is insufficient.

## Verification performed

- Recomputed the executable hash and retained the PE image-base convention.
- Re-ran RTTI parsing for the direct HID, streamed file/HID/YTUN, packet-parser,
  connector, and reconnect classes.
- Compared child and parent VMTs, including parent links that use direct TypeInfo VAs.
- Recovered the `H`/`I`/`J` encoder at `[0x00F98E98, 0x00F99049)` and independently
  checked all three opcodes against the receive selector and target tables.
- Checked the named send, heartbeat, retry, parser, and streamed delegation ranges
  instruction-by-instruction with `objdump`. The IDC contains no `MakeFunction` ranges
  for these methods, so their endpoints were not claimed as IDC-derived.
- Added/updated focused synthetic-PE tests for RTTI pointer-cell and direct-TypeInfo
  input, parent VMT comparison, and IDC half-open ranges.

Not validated: live timing, physical disconnect behavior, YTUN wire equivalence,
every receive-dispatch branch, or a full mapping from all application types to
response/correlation keys. No device operation was used to validate these findings.
