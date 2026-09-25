# API server communication hardening roadmap

Date: 2026-07-14

Status: proposed; no implementation work from this roadmap has started.

Basis: comparison of the current API-server direct-HID implementation with the
statically recovered F-Link communication boundaries documented in
`2026-07-14_f-link-communication-protocol-boundaries.md`.

## Goal

Make the long-running API-server connection resilient to fragmented messages,
interleaved asynchronous events, short or failed writes, a silent-but-open panel, and
USB re-enumeration without changing the public API or weakening panel-side
authorization.

The implementation should preserve these invariants:

- exactly one component owns reads from a HID descriptor;
- every valid incoming application packet is dispatched or explicitly accounted for,
  never silently consumed by an unrelated request;
- physical-report retry, application-command retry, heartbeat/liveness, and reconnect
  remain separate policies;
- a request cannot report success without its required response or state transition;
- direct short frames and streamed `H`/`I`/`J` frames use separate, tested codec states;
- Linux `hidraw` report-ID and padding behavior is verified before copying the Windows
  65-byte write convention.

## Phase 1: introduce the transport codec

Priority: highest. This is the prerequisite for every later phase.

Create a transport-level codec used by `JablotronUSBClient`, independent of domain
packet parsing.

Required behavior:

1. Encode and decode ordinary application frames as
   `type || one-byte payload length || payload`.
2. Validate that a complete short frame is present before emitting it. Reject or retain
   incomplete data according to explicit codec state; never emit a truncated slice.
3. Implement the recovered long-frame envelope exactly:
   - `0x48` (`H`) initial report;
   - `0x49` (`I`) continuation report;
   - `0x4A` (`J`) terminal report;
   - first fragment carries application type, capped `0xFA` length, and 59 payload
     bytes;
   - later fragments carry at most 62 bytes;
   - fragment count is `(application_frame_length + 62) div 62`.
4. Enforce sequence, remaining-fragment, maximum-size, and reconstructed-length
   checks. Reset with a diagnostic reason after malformed input.
5. Keep packing of multiple complete short frames within a 64-byte HID payload.
6. Refuse a single frame larger than the direct limit unless it has been encoded into
   the `H`/`I`/`J` envelope.

Acceptance criteria:

- exact encoder and decoder vectors for one-, two-, and three-fragment messages;
- round trips at lengths 61, 62, 63, 64, 123, 124, 250, and above 250;
- tests for missing `I`, early `J`, duplicate `H`, wrong count, oversized reassembly,
  padding, multiple short frames, and truncated short frames;
- current short login, heartbeat, section, PG, system-info, device-state, and
  diagnostics packets remain byte-for-byte unchanged.

## Phase 2: establish one receive owner and central dispatcher

Replace request-specific reads with one continuous receive owner. It should feed raw
reports through the Phase 1 codec and dispatch completed application packets.

Required behavior:

1. The receive owner is the only code that calls `read`/`select` on the HID descriptor.
2. Asynchronous device-state/fault packets always reach the live-state parser, even
   while login, control, system-info, snapshot, or diagnostics work is pending.
3. Request waiters register predicates using the strongest available correlation:
   packet type, subtype/command, device or router, requested section/PG, and expected
   state.
4. A packet may update asynchronous state and satisfy a waiter when both uses are
   appropriate.
5. Unmatched packets go to a bounded diagnostic queue or counter; no request loop
   silently discards them.
6. Shutdown and reconnect cancel all outstanding waiters with a transport-specific
   exception.

Migration target: remove direct `client.read_packets()` loops from login,
authorization refresh, PG/section confirmation, snapshots, diagnostics, and
system-information queries after equivalent dispatcher waiters exist.

Acceptance criteria:

- an interleaved motion on/off burst is delivered while every request type is waiting;
- two logically adjacent requests cannot consume each other's response;
- no concurrent descriptor reads occur;
- reconnect deterministically wakes all blocked operations.

## Phase 3: add explicit liveness and mandatory-response contracts

The current exact heartbeat `52 01 02` remains the liveness probe, but successful
`write` completion must not be treated as proof that the panel is responsive.

Required behavior:

1. Track last valid receive time, last transmit time, last heartbeat time, and current
   session state.
2. Define a silence deadline and escalate through unhealthy, close, reconnect, and
   re-authenticate states. F-Link's `3 * ping delay` behavior is a useful initial model,
   but the final Linux timings must be capture- and test-backed.
3. Define mandatory replies for login, base snapshot, control, and system information.
4. A snapshot without the required fresh section/PG response is a communication
   failure, not a successful empty snapshot.
5. A system-information query missing required fields raises a timeout/result error
   rather than returning an all-`None` success value.
6. Expose structured counters/timestamps for last valid RX, heartbeat timeout,
   reconnect reason, and consecutive failures without logging private packet content.

Acceptance criteria:

- a writable but silent fake panel becomes unavailable within the configured deadline;
- the next permitted reconnect reopens, logs in, restores streaming, and clears the
  failure streak;
- stale data is not published as a fresh successful result.

## Phase 4: harden physical writes

Required behavior:

1. Check the return count from every `os.write`.
2. Handle `BlockingIOError`, interrupted calls, and short counts with a bounded
   deadline and writable polling where supported.
3. Apply bounded retries at the physical-report layer. Do not automatically repeat a
   complete application command when delivery may already have occurred.
4. Keep application-level command retry explicit and tied to missing confirmation.
5. Reject empty writes and oversized unfragmented writes.
6. Capture or otherwise safely verify Linux `hidraw` report-ID/padding semantics before
   forcing 64-byte padding or adding the Windows report-ID byte.

Acceptance criteria:

- deterministic tests for short write, `EAGAIN`, `EINTR`, timeout, device removal,
  and successful retry;
- no empty write when a single application frame exceeds 64 bytes;
- a physical failure and an application timeout produce distinct errors and metrics.

## Phase 5: strengthen request correlation and command policy

Required behavior:

1. PG confirmation must match the requested PG and desired value; a generic toggle
   packet for another PG is insufficient.
2. Section confirmation continues to match the requested section and permitted target
   states, but moves onto dispatcher predicates.
3. System-information responses match each requested subtype and report missing
   subtypes explicitly.
4. Diagnostic responses match device/router context, including reconstructed `0x94`
   and `0x96` messages.
5. Preserve the existing one-time authorization refresh and command retry, but make
   retry eligibility explicit per command.
6. Drain operations become dispatcher barriers or timestamped stale-response filters,
   not destructive reads.

Acceptance criteria:

- unrelated PG, section, device, and diagnostic responses cannot create false success;
- late responses are classified and cannot satisfy a newer incompatible request;
- authorization failure restores or closes the prior session deterministically.

## Phase 6: fault matrix, rollout, and observability

Add integration tests with a fake HID endpoint covering:

- short and `H`/`I`/`J` traffic in both directions;
- multiple application frames in one report;
- asynchronous events interleaved with every request class;
- malformed length/count/sequence input;
- panel silence with an open descriptor;
- partial writes and physical timeouts;
- device removal and `/dev/hidrawN` renumbering;
- reconnect during outstanding requests;
- shutdown during read, write, retry, and reconnect.

Roll out behind structured transport diagnostics. Preserve the existing public API and
make the codec/dispatcher change independently reversible. Remove the old direct-read
paths only after parity tests cover every currently used command.

## Deferred scope

- YTUN transport implementation should follow stabilization of the direct-HID codec
  and dispatcher. The common VMT boundary is known, but YTUN wire equivalence is not.
- Firmware-update commands and package handling are not required for API-server
  communication hardening.
- Adding new live panel operations is outside this roadmap; validation should prefer
  synthetic endpoints and existing sanitized captures.

## Recommended first implementation slice

The smallest high-value slice is Phase 1 receive-only decoding plus tests, followed by
feeding its completed short packets into the existing parser. It can prove `H`/`I`/`J`
reassembly without changing command scheduling. The next slice should introduce the
single receive owner for asynchronous device-state packets before migrating control
and diagnostics waiters one at a time.
