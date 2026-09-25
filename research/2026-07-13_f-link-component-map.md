# F-Link 2.9.2.1509 Component Map

Date: 2026-07-13

## Purpose

This report maps the major components of F-Link before deeper function-level reverse
engineering. It is intended as a navigation aid for the unpacked executable and its
existing IDA/IDR artifacts, not as a claim that every class or call edge is understood.

The most useful conclusion is that F-Link is not one monolithic protocol engine. It has
four separable domain layers:

1. a central/panel model and plugin layer;
2. schema-driven configuration objects and MessagePack-backed panel files;
3. interchangeable physical transports (HID, streamed HID, file and YTUN); and
4. feature controllers such as firmware update, users, peripherals, events and
   registration.

Future work should start at the domain-specific anchors below and avoid spending time
inside the statically linked Delphi/VCL, Spring4D, XML and TeeChart implementations
unless a call from domain code requires it.

## Analyzed Artifacts

All executable addresses in this report are virtual addresses (VA) for image base
`0x00400000`. Unless a row explicitly says `code`, `function` or `string`, a class
address is the recovered RTTI record used as a stable search anchor. It is not a method
entry point or necessarily the class VMT.

| Artifact | Size | SHA-256 | Use |
| --- | ---: | --- | --- |
| `F-Link.exe` | 9,587,968 | `09f92fe651b919faded4c0a194cca3e9d73f20d59993365fd8b4881d8c900cfe` | Original UPX-packed executable |
| `F-Link.unpacked.exe` | 28,215,552 | `3ae9e67b324a672a589e2b4dd3a4adb4ff07bb90de00d7d47a9f6f85c6bdcd04` | Primary static-analysis target |
| `F-Link.unpacked.idc` | 67,681,917 | `86ac68c89db1c2ce036d0106af4a92836623efc5653d09135417ec6f2d215706` | IDR-produced names, functions, RTTI and comments |
| `F-Link.unpacked.map` | 960,481 | `220505772682c206e4ca68ec2c3ef0eb804d604b707bb6750e0c3f11a33f99a2` | Delphi/runtime public symbols |
| `Peskova F-Link.DMP` | 153,033,800 | `81117d3e68028e31a88a97866fbbd44bdfc3df8573f13e8f54191618d1a4a75d` | Runtime memory and object/string correlation |

The unpacked PE is 32-bit x86 Delphi. Its primary `.text` spans
`0x00401000-0x011BF844`; `.itext` starts at `0x011C0000`, and the entry point is
`0x011C7754`. IDR recovered 5,637 class RTTI records, including 2,790 generic class
instantiations, plus 17,326 function ranges and roughly 25,000 non-RTTI names. These
figures explain both the strong type visibility and the substantial template/library
noise.

## High-Level Data Flow

```text
TMainForm / feature controllers
        |
        v
TCentral100MainFormPlugin -> TCentral100 / TCentral100CommunicablePlugin
        |                                  |
        |                                  +-> users, peripherals, events, RF, firmware
        v
Central100Storage objects <-> ConfigDOM/schema <-> MessagePack file wrappers
        |                                           |
        |                                           +-> FLEXI_/EXPORT/IMPORT file path
        v
TJA100*Comm facade -> packet parser/buffering -> HID | streamed HID | file | YTUN
```

The UI and feature plugins generally operate on model objects rather than directly on
USB. Configuration serialization and communication are therefore good independent
reverse-engineering targets.

## Component Inventory

### 1. Application Shell and Plugin Orchestration

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TMainForm` | `0x0101AB38` | Top-level application form and modal/plugin host | High |
| `TfrmSelectCentral` | `0x010108F8` | Panel selection/connection UI | High |
| `TCentral100MainFormPlugin` | `0x00E452AC` | Connects the JA-100 central implementation to the main form | High |
| `TCentral100Plugin` | `0x00EC6BC0` | Base feature plugin | High |
| `TCentral100CommunicablePlugin` | `0x00EC6D98` | Plugin base with access to panel communications | High |
| `TMultiLinkAPI` | `0x00ACE870` | Generic application/API boundary | Medium |
| `TCentral100API` | `0x00AD6D3C` | JA-100-specific API wrapper | Medium |

`TMainForm` is the best anchor for startup, plugin registration and user-action call
chains. It is a poor starting point for protocol details because it delegates those to
the central and feature plugins.

### 2. Central/Panel Lifecycle

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TCentral100` | `0x00E421C0` | Main JA-100 panel controller/session object | High |
| `TCentral100Facelift` | `0x00E43E84` | Facelift-generation specialization | High |
| `TCentral100Small` | `0x00E44748` | Small-panel specialization | High |
| `TCentral100K` | `0x00E44A34` | K-series specialization | High |
| `TJA100ExitService` | `0x0104AE44` | Service/configuration-mode exit workflow | High |
| `TJA100Maintenance` | `0x0104B0E4` | Maintenance-mode workflow | High |
| `TCentral100ReconnectCU` | `0x00BA7CC0` | Reconnect and wait-for-central orchestration | High |
| `TCentral100DeviceObstructions` | `0x010909B8` | Blocking-condition and obstruction handling | High |

This layer owns state transitions such as connect, enter service, load/upload data,
wait for background talkers, reconnect and exit. Existing live-capture work should be
correlated primarily with methods on these types rather than with the UI.

### 3. Configuration Schema and DOM

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TSchemaReader` | `0x00823474` | Loads the embedded configuration schema | High |
| `TConfigReader` | `0x0091F6C4` | Loads configuration restrictions/expressions | High |
| `TDOMObject` family | `0x008A352C` onward | Typed in-memory schema values | High |
| `TDOMSerializer` | `0x00F0DFCC` | Serializes configuration DOM values | High |
| `TDOMDeserializer` | `0x00F0FC1C` | Deserializes values into the DOM | High |

The embedded schema already recovered by `f_link_schema_tool.py` is not merely UI
metadata. RTTI shows a complete typed DOM with primitive, enum, set, string, blob,
record and array variants. This is the semantic layer above raw MessagePack field
numbers. When naming fields in `EXPORT.CFG` or `IMPORT.CFG`, use this layer as the
source of truth.

### 4. Panel Model and Stored Configuration

The concrete model is spread over many types, but the principal roots and collections
are identifiable:

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TJA100History` | `0x00EC234C` | Central history/version records | High |
| `TJA100CentralInfoStore` | `0x00EC39FC` | Central metadata and persistent information | High |
| `TCentral100Users` | `0x00E2C380` | User feature/model controller | High |
| `TCentral100Peripherals` | `0x00DDA0BC` | Peripheral collection/controller | High |
| `TCentral100Sections` | `0x00AE7888` | Section collection/controller | High |
| `TJA100Collection<TJA100User>` | `0x00F6ED2C` | User storage collection | High |
| `TJA100Collection<TJA100Section>` | `0x00F6F8E4` | Section storage collection | High |
| `TJA100Collection<TJA100PG>` | `0x00F70D30` | Programmable-output collection | High |

The `0x00F6D000-0x00F79B00` region contains instantiated collections for users,
sections, user time limits, PGs, reports, ARC/PCO records, bypasses, texts, calendars,
thermostats and related objects. This is a productive range for recovering field
accessors and cross-referencing schema names to concrete Delphi properties.

### 5. Configuration Files and MessagePack

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TCentral100Stream` | `0x00F2C134` | Base stream abstraction for panel files | High |
| `TCentral100File` | `0x00F2CCC4` | Logical panel file | High |
| `TCentral100PhysicalFile` | `0x00F2D770` | Physical file-backed implementation | High |
| `TCentral100CustomMsgPackFile` | `0x00F2DF28` | MessagePack-aware file base | High |
| `TCentral100MemoryStream` | `0x00F2E124` | In-memory stream implementation | High |
| `TCentral100StreamFile` | `0x00F2E314` | File layered over a stream | High |
| `TCentral100MsgPackFile` | `0x00F2E594` | MessagePack physical/logical file | High |
| `TCentral100MsgPackMemoryStream` | `0x00F2E7A0` | MessagePack in-memory implementation | High |
| `TCentral100MsgPackStreamFile` | `0x00F2E9B8` | MessagePack stream-file implementation | High |

Strings explicitly name `export.cfg`, `import.cfg`, `flexi_.cfg`, `FLEXI1.CFG` and
`FLEXI2.CFG`, and log methods named `TCentral100CustomMsgPackFile.ReadVersionedText`
and `TCentral100MsgPackFile.FlushBuffers`. This component is the best static target for
formalizing file headers, version handling, XOR/obfuscation placement and commit/flush
semantics. It is separate from the low-level transport classes.

Database/export anchors include `TDBExport` at `0x00EC3C04`, `TJA100FDEExport` at
`0x00EC3DB0`, `TJA100FDRExport` at `0x00EC3F10`, and `TJA100InfoExport` at
`0x0112D8AC`. These cover workstation `.fdb` persistence and user-facing `.fde`/report
exports rather than the live panel file protocol.

### 6. Physical Communication Stack

The transport architecture is visibly layered:

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TJA100USBDeviceConnector` | `0x00B55CD0` | USB device discovery/selection | High |
| `TJAHIDComm` | `0x00F9949C` | Generic Jablotron HID transport | High |
| `TJA100CustomHIDComm` | `0x00F99790` | JA-100 HID base | High |
| `TJA100HIDComm` | `0x00F99CBC` | Central HID communications | High |
| `TJA100PeripheralComm` | `0x00F99ED4` | Peripheral-addressed communication facade | High |
| `TPacketParser` | `0x00F9AE70` | Packet framing/parsing | High |
| `TJA100FileComm` | `0x00F9B368` | File-backed/demo communications | High |
| `TJA100StreamedComm` | `0x00F9BB6C` | Stream-oriented communication base | High |
| `TJA100BufferedComm` | `0x00F9C1F0` | Buffered communication layer | High |
| `TJA100StreamedHIDComm` | `0x00F9C6DC` | HID transport through streamed framing | High |
| `TJA100StreamedYTUNComm` | `0x00F9CA38` | YTUN transport through the same framing | High |

The import table confirms direct use of `hid.dll` and SetupAPI for enumeration and
capabilities. The sibling streamed HID/YTUN types indicate that higher protocol layers
are intentionally transport-independent. A packet/state-machine function found above
`TJA100StreamedComm` should therefore be checked for use by both local USB and remote
YTUN sessions.

Older generic communication primitives also exist around `0x0071884C` (`TCommThread`,
`TCommBase`, RS-232 and HID helpers). Treat these as lower-level library plumbing until
a JA-100 class calls them.

### 7. YTUN, Network and Remote Registration

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TYTUNAddrResolver` | `0x00AFFC68` | Resolves YTUN endpoints | High |
| `TYTUN100Com` | `0x00EAA084` | JA-100 YTUN communication object | High |
| `TYTUN100Stream` | `0x00EAB710` | Countered YTUN stream | High |
| `TYTUNSocket` | `0x00EACD04` | YTUN socket wrapper | High |
| `TYTUNThread` | `0x00EAD510` | YTUN worker thread | High |
| `TYTUN100Interface` | `0x00EB2A0C` | YTUN interface adapter | High |
| `TCentral100Registration` | `0x00BFBB1C` | Device/service registration workflow | High |

Network functionality uses WinInet and Winsock imports, while Windows CryptoAPI is
imported for random generation, key import and encrypt/decrypt operations.
Static strings mention RSA authentication and YTUN public-key loading. These facts do
not imply that firmware is decrypted by F-Link; the captured firmware path proves that
the peripheral payload is forwarded unchanged. Crypto call xrefs should instead be
classified first as YTUN, credentials, language files, history, or package validation.

### 8. Peripheral Models and Setup Controllers

F-Link embeds a large device catalogue rather than loading one generic descriptor at
runtime. Major model clusters include:

| Approximate range | Family/examples |
| --- | --- |
| `0x00A31EC8-0x00A35554` | Remote controls, keys and buttons (`PRF100RC`) |
| `0x00A53E24-0x00A6B118` | Keyboards/keypads, including JA-113E and JA-1x6E (`PRF100Keyboard`) |
| `0x00A767E4-0x00A86080` | PIR, smoke, radio, camera, output and miscellaneous peripherals |
| `0x00B7E63C-0x00B82FB8` | Thermostats and schedules (`PRF100Thermostat`) |
| `0x00B8EC88-0x00B94758` | Internal/external sirens (`PRF100Siren`) |

This matters for firmware analysis: applicability logic may be implemented in the
specific periphery class as well as in package metadata. For the captured JA-113E
update, start with `TJA100PeripheryKeyboardJA113E` at `0x00A58758` and
`TJA100PeripheryKeyboardJA113ENew` at `0x00A59E6C`, then follow references into the
generic firmware update layer.

### 9. Firmware and Software Update Subsystems

There are three related but distinct update paths:

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TJAPacker` | `0x00A907F4` | `JAPKG` container reader/decompressor | High |
| `TFWFParseThread` | `0x00A9EA64` | Background `.fwf` package parser | High |
| `TPeripheralsUpdate` | `0x00A9E688` | Parsed periphery-update catalogue | High |
| `TJA100DownloadUpdate` | `0x00B01F1C` | F-Link application update metadata/download | High |
| `TUpdateUtils` | `0x00B4D8B4` | Generic application updater | High |
| `TfrmJA100UpdateFW` | `0x00BBBC4C` | Firmware-update UI | High |
| `TCentral100UpdateFW` | `0x00BD03E0` | Panel-level firmware orchestration | High |
| `TCentral100UpdateFWUtil` | `0x00BD0498` | Update selection/check helpers | High |
| `TJA100UpdateFWInfoItem` | `0x00EC35C0` | One firmware candidate/descriptor | High |
| `TJA100UpdateFWInfo` | `0x00EC38A0` | Firmware candidate collection | High |
| `TPRFUpdate` | `0x00F8E4F0` | Low-level peripheral firmware state machine | High |

Expected call/data path:

```text
TfrmJA100UpdateFW
  -> TCentral100UpdateFW / TCentral100UpdateFWUtil
  -> TFWFParseThread + TJAPacker
  -> TJA100UpdateFWInfo(Item) and extracted TStream
  -> TPRFUpdate
  -> TJA100PeripheralComm
  -> TJA100*HIDComm or YTUN transport
```

Known string anchors refine this map:

| Code/string address | Meaning |
| ---: | --- |
| code `0x00F8FD00`, string `0x00F903F4` | Extracted package member logged as `Binary %s extracted to stream` |
| function start `0x00F91158`, string `0x00F91238` | Calculates firmware block/frame counts from stream size |
| code `0x00F9399C`, string `0x00F94704` | Completion accounting: confirmed and unconfirmed blocks |

The package parser and updater are worth reversing for format validation, device
matching, boot-entry token generation and protocol semantics. They are not promising
firmware-decryption targets because the captured wire payload equals the package
payload byte-for-byte after the 512-byte member header is removed.

### 10. Events, Diagnostics and Reports

| Anchor | Address | Role | Confidence |
| --- | ---: | --- | --- |
| `TCentral100EventsPlugin` | `0x010E4D84` | Event-log feature plugin | High |
| `TCentral100EventsControl` | `0x010E58D8` | Event presentation/filtering | High |
| `TCentral100RFMonitor` | `0x00BC6364` | RF measurements and live monitor | High |
| `TVoiceConvertor` | `0x00BCFEBC` | Voice asset conversion | High |
| `TJA100UpdateMessageLogger` | `0x00BA7810` | Update/reconnect message logging | High |
| `TSentrySDK` | `0x00A1EBDC` | Crash/telemetry reporting | High |

The event plugin should be the main entry point for correlating `FLEXI_LOG`, memory
event reads and the event export formats. `TfrmPacketWindow` at `0x00FFA6A8` and
`TPacketList` at `0x00FFA748` are likely useful diagnostic UI objects for discovering
internal packet representations.

## Bundled Libraries and Noise Boundaries

The executable statically links substantial framework and third-party code. These are
usually not first-choice targets:

| Range/indicator | Component |
| --- | --- |
| low `.text`, numerous `System.*`/`Vcl.*` names | Delphi RTL and VCL |
| generic names containing `Spring.*` | Spring4D collections, reflection and serialization |
| `0x00C04860` onward, `TGP*` | GDI+ wrapper |
| much of `0x00C22230-0x00CEFFFF`, `TTee*` | TeeChart and graphing |
| `0x00CEFFE0-0x00D06CB8`, `TDOM*`/`TXML*` | General XML parser/DOM implementation |
| `TPerlRegEx` at `0x00A19BF4` | PCRE wrapper |
| `TZipFile` at `0x00B59E50` | ZIP implementation |

The custom schema DOM at `0x008A....` and serialization DOM at `0x00F0....` are
domain-relevant despite their generic-looking names. They should not be discarded with
the general XML DOM.

## External Interfaces

The imported DLLs support the component map:

- `hid.dll` and `setupapi.dll`: HID discovery and I/O;
- `wininet.dll`, `URLMON.DLL`, `wsock32.dll`, `icmp.dll`, `iphlpapi.dll`: HTTP,
  sockets, reachability and network enumeration;
- `advapi32.dll`: credentials, registry and CryptoAPI;
- `wintrust.dll`: executable/package signature verification;
- `dbghelp.dll`: exception stack collection;
- `ole32.dll`/`oleaut32.dll`: browser, COM and automation wrappers;
- standard VCL-facing graphics, shell, print and UI libraries.

The application also exposes public update, registration, telemetry and YTUN endpoint
strings. Endpoint xrefs are useful for locating network clients, but the strings alone
should not be treated as evidence that a service is still active or accepts the same
protocol.

## Recommended Reverse-Engineering Order

1. **Recover class methods and call graphs at the boundaries.** Import the IDC into the
   existing IDA database, then name VMT methods for `TCentral100`,
   `TCentral100CommunicablePlugin`, `TJA100PeripheralComm`,
   `TCentral100CustomMsgPackFile`, `TJAPacker` and `TPRFUpdate`.
2. **Map the file protocol independently.** Trace `ReadVersionedText`, `FlushBuffers`
   and the logical-to-physical file wrappers. Correlate with Procmon and USB captures.
3. **Map packet dispatch.** Recover `TPacketParser` output structures, then identify the
   command dispatcher used by `TJA100HIDComm` and `TJA100PeripheralComm`.
4. **Map lifecycle states.** Trace enter-service, configuration accepted/rejected,
   reconnect and `TJA100ExitService`, labeling captured `0x52`, `0x80`, `0x94` and
   `0x96` messages as call sites are found.
5. **Then deepen firmware update analysis.** Follow the update path above, focusing on
   header validation, applicability selection, command construction, ACK/retry handling
   and the dynamic boot-entry token.
6. **Use the minidump for validation.** Runtime strings and object layouts can confirm
   static field guesses, but secrets or customer data in memory must not be copied into
   reports.

## Working Conventions

- Record executable locations as VA and include the image hash in every analysis note.
- Prefix inferred function names with their confidence or keep an adjacent comment;
  IDR's recovered type name is evidence, while a guessed method role is not.
- Separate protocol facts observed on the wire from behavior inferred from a string
  xref or decompilation.
- Keep F-Link software-update code distinct from central firmware and peripheral
  firmware update code.
- Treat generic instantiations as type evidence, not separate conceptual components.
- Search UTF-16 strings and RTTI before broad disassembly. Delphi exception messages,
  class names and nested anonymous-method RTTI provide unusually strong landmarks.

## Current Gaps

- The original Delphi unit names are only partially recoverable. Generic RTTI exposes
  many units (`Central100Storage`, `JA100_Comm`, `PRF100Keyboard`, and others), but IDR
  assigns synthetic unit names to much of the map.
- The existing IDR export did not functionize much of the `TPRFUpdate` region, so its
  method boundaries and VMT slots still need manual recovery.
- The exact boundary between HID reports, JA-100 packet framing and command dispatch is
  not yet labeled end-to-end.
- The configuration file wrappers are mapped by type and strings, but their read/write
  pipelines have not yet been reconstructed as call graphs.
- Network and CryptoAPI call sites have not yet been classified by subsystem.

These gaps are narrower than a fresh executable-wide analysis. The next static pass can
work component by component using the anchors above.
