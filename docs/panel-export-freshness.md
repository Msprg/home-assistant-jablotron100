# Can the panel's configuration be read without entering configuration mode?

Investigated 2026-08-21 against the live JA-107K. Short answer: **no.** The
untriggered read is not merely stale — between sessions the panel leaves
`EXPORT.CFG` as one megabyte of zeros. The refresh sequence is not an
optimisation to be skipped; it is the only thing that puts data on the
volume at all.

The second question turned out well: **our reads do not emit panel event 44
or 48**, so they do not poison the tripwire `board` uses to notice that
somebody else wrote to the panel.

## Method

Everything below was measured read-only. Most of it needed no panel session
at all: the FlexiCFG and FlexiLog volumes are ordinary FAT16 mass storage,
so directory entries, timestamps and file contents can be read with raw
block reads (`read_device_direct_bytes`) — no serial port, no login, no
protocol.

Three configuration-mode sessions were performed in total:

1. one triggered export pull, driven through the running server
   (`GET /v1/export/time-limits`, which forces `pull_catalog_snapshot`);
2. one event-log read from the host (`jablotron_event_tool recent`), which
   required stopping the API container for 56 s because the container has no
   `CAP_SYS_ADMIN` and the server holds `/dev/hidraw0` open;
3. the catalog pull that the container performs on startup, an unavoidable
   consequence of restarting it after (2).

No writes of any kind. A temporary `config:read` token was minted for (1)
and revoked afterwards (`tmp-freshness-probe`, id `fdecd567…`, used once).

## Finding 1 — an untriggered read returns nothing at all

`read_export_direct()` follows the FAT chain of `EXPORT.CFG` on FLEXI_CFG.
Run three times, one second apart, with no session open:

```
run0: 3.54s size=1048576 sha256=30e14955ebf13522… users=0 sections=0 pgs=0 main_config=no
run1: 3.45s size=1048576 sha256=30e14955ebf13522… users=0 sections=0 pgs=0 main_config=no
run2: 3.47s size=1048576 sha256=30e14955ebf13522… users=0 sections=0 pgs=0 main_config=no
```

`30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58` is the
SHA-256 of 1 MiB of zero bytes. The file's data clusters are empty. The read
path itself is fine — the same technique read the FAT boot sector, the root
directory and the allocation table correctly in the same run.

The directory entry is not empty, though: it carries a real size and a real
modification time.

```
'EXPORT  CFG' attr=0x22 size=1048576 cluster=2 written=2026-08-19 11:31:32
```

So the panel had rewritten the file 38 hours earlier, and what it left
behind is zeros.

**After** the triggered pull in probe 1, the same directory entry read

```
'EXPORT  CFG' attr=0x22 size=1048576 cluster=2 written=2026-08-21 03:58:52
```

— the trigger does rewrite the file, and the panel clock is local time
(CEST), 2 hours ahead of the host's UTC. But an untriggered read taken 5
seconds after that pull completed **still returned 1 MiB of zeros**.

The conclusion is stronger than "stale": the configuration data exists on
the volume only while a session holds it there. Nothing about an untriggered
read can be made current, so there is nothing to fail safe about — it must
trigger.

## Finding 2 — the volume is a pull-populated surface, not a live mirror

The same is true of the event log, which is what makes the mechanism clear.
With no session open, `FLEXILOG.TXT` (10,539,736 B) scanned end to end was
**entirely zeros**, the last megabyte of `FLEXILOG.OLD` (95,027,200 B) was
zeros, and `LOGINDEX.BIN`'s newest checkpoint was 2026-06-11 — over two
months old on a panel that logs continuously.

During probe 2's setup-mode session the same files came back populated: a
2 MiB window with 30,510 records spanning 2026-07-13 07:16 to 2026-08-21
04:00:59. This is exactly why `pull_live_archive` does
`perform_login` → `enter_setup_mode` **before** it mounts the volume.

So the panel materialises mass-storage content on demand and clears it
afterwards. It does not maintain either volume as a live mirror.

## Finding 3 — a configuration change does not leave a readable EXPORT.CFG

Directly asked, the question "does the panel regenerate `EXPORT.CFG` when
the config changes?" is moot given Finding 1: even if it did, the content
does not survive to the next untriggered read.

What the log shows is that every regeneration lines up with a *session*, not
with a change:

| Panel-local time | Event | EXPORT.CFG mtime |
| --- | --- | --- |
| 2026-08-19 10:40:25 | `48 Zmena konfigurácie`, user 4, channel Server | (IMPORT.CFG mtime 10:40:22) |
| 2026-08-19 11:26:22 | `48 Zmena konfigurácie`, user 4, channel Server | — |
| 2026-08-19 11:31:27–11:31:45 | cloud session: `156` → `150 Autorizácia OK` (user 601 Server) → `157` | **11:31:32** |

The refresh at 11:31 belongs to the session at 11:31, five minutes after the
change — not to the change itself.

**This installation is not hypothetically at risk of invisible changes; it
has had three in five days.** `48 Zmena konfigurácie` appears on 2026-08-17
at 14:24:28 and on 2026-08-19 at 10:40:25 and 11:26:22, all over the LAN/
cloud "Server" channel. The 08-17 one is visible in our own artefacts: two
CLI `user-tool-list` pulls 94 seconds apart returned 95 users and then 88.
The API server's cached catalog, pulled at container start on 2026-08-17
10:15 UTC, saw none of it.

## Finding 4 — our reads do not emit event 44 or 48

This is the one that matters for `board`'s tripwire, and the answer is
clean. Probe 1's triggered export pull ran 03:58:31–03:58:47 panel-local.
Every event the panel logged in that window:

```
260821 03:58:47 code=150 'Autorizácia OK' src='Užívateľ 100: Api-server' ch='USB'
260821 03:59:02 code=150 'Autorizácia OK' src='Užívateľ 100: Api-server' ch='USB'
```

Two authorisations — the refresh sequence's login and `cleanup_read_session`'s
login — and nothing else. **No 44. No 48.**

The same signature appears for the server's startup pull on 2026-08-17:

```
260817 12:15:25 code=156 'Spojenie nadviazané'   ch='USB'
260817 12:15:25 code=150 'Autorizácia OK'  src='Užívateľ 100: Api-server' ch='USB'
260817 12:15:40 code=150 'Autorizácia OK'  src='Užívateľ 100: Api-server' ch='USB'
```

and for the two CLI pulls on the same day (one `150` each, attributed to
`Užívateľ 7` because the CLI authenticated with a different code).

Across the whole 39-day window the log contains **10** events with these
codes: `44 Vstup do režimu servis` three times (2026-07-13 16:42 and 16:55
over USB, 2026-07-23 16:51 over Server) and `48 Zmena konfigurácie` seven
times, every one of them an actual configuration change over the cloud
channel. None of them coincides with any of our reads.

Two caveats worth stating plainly:

- The F-Link export refresh sequence leaves the panel in
  `CONFIGURATION_SECTIONS_MODE` (which is why `cleanup_read_session` checks
  for it), but the panel evidently does not consider that "service mode" for
  logging purposes. It is not event 44.
- Our reads are not invisible: each one logs `150 Autorizácia OK` attributed
  to `Užívateľ 100: Api-server` over channel USB. If `board` ever widens its
  tripwire from {44, 48} to authorisation events, it will start seeing every
  catalog read. Keep the tripwire on 44/48.

## Finding 5 — what each path costs

| Operation | Wall clock | Panel sessions | Events emitted |
| --- | --- | --- | --- |
| Untriggered `read_export_direct()` | **3.45–3.58 s** | none | none |
| Parse (`extract_export_catalog`, 1 MB blob) | 0.92 s | — | — |
| Triggered pull, end to end via the API | **15.87 s** | 1 (2 logins) | `150` ×2 |
| Container start (catalog + system + status) | ~65 s | 1 | `156`, `150` ×2 |

The triggered pull decomposes as roughly 3.5 s of raw read, ~1.1 s of
parsing and ~11 s of trigger-plus-cleanup protocol. The panel log
corroborates it independently: the startup pull's two authorisation events
are 15 seconds apart (12:15:25 → 12:15:40), matching the 15.87 s measured at
the HTTP boundary.

The untriggered read being cheap is not useful, since it returns nothing.
The number that matters for the cache design is **~16 s per catalog pull**,
which is why concurrent readers must coalesce into one pull rather than
queue three.

## What this changes in the design

1. **Every catalog read triggers.** `trigger_used` is reported as `true` on
   any response whose data came from a panel read, because there is no other
   kind of panel read.
2. **A pull is expensive and observable**, so it must be demand-driven and
   single-flight. Nothing refreshes the catalog on a timer.
3. **The FAT16 read race** that `pull_catalog_snapshot` retries for is very
   likely this same phenomenon — a read landing outside the window in which
   the file is materialised comes back empty, and the existing
   "retry once without reset if the catalog is fully empty" is exactly the
   right response. The untriggered read path is not used by the server, so it
   needs no equivalent care; the raw reads performed for this investigation
   were repeated and hash-compared instead (three identical hashes).

## What could not be determined

- **Whether a configuration change alone regenerates `EXPORT.CFG`.** Every
  regeneration observed coincides with a session. Answering it definitively
  would need a config change made with no session reading it back, which
  means writing to the panel. It does not affect the design: the content
  does not survive to the next untriggered read either way.
- **Whether skipping `cleanup_read_session` would leave the file
  materialised.** Not tested — every server path cleans up, and leaving the
  panel in configuration mode to keep a file readable would be a bad trade.
- **Whether a panel *write* (IMPORT.CFG apply) emits 44 or 48.** No writes
  were performed. The log strongly suggests 48 accompanies any real config
  change regardless of channel, so a write by this server should be expected
  to emit 48 — but that is inference, not measurement.
- **`/v1/events` could not work in the deployed container.** Fixed on
  2026-08-21; see "Postscript" below.


## Postscript (2026-08-21): the event endpoint, and what it does not buy

`/v1/events` returned 500 in the container. Two independent pre-existing
defects, both now fixed:

1. **It tried to mount FLEXI_LOG.** The first failure was not the capability
   wall but `FileNotFoundError: 'sudo'` — the image ships no `sudo` binary
   and `mount_device` shelled out to it unconditionally, although the
   container already runs as root. Bypassing that only reaches the second
   wall: `mount(2)` needs `CAP_SYS_ADMIN` and `CapEff=0x00000000a80425fb`
   has bit 21 clear. Both are avoided by not mounting: `FatVolumeReader`
   reads the volume with raw block reads, the same technique the export path
   has always used for `EXPORT.CFG`. Measured on the live volume: geometry
   plus directory in 0.28 s, `LOGINDEX.BIN` in 0.25 s, a 64 KiB window in
   0.25 s. The `sudo`-when-root fix landed too, since the user-write path
   hits the identical wall (see below).

2. **The window ended in the past.** `pull_live_archive` accepts
   `end_mode` of `"index"` (end at the newest `LOGINDEX.BIN` checkpoint) or
   `"physical"` (end at the live `FLEXILOG.OLD`+`TXT` sizes). The API
   service passed `"logical"` — neither — which silently fell through to the
   index path. `LOGINDEX.BIN` on this panel is checkpointed roughly daily
   and currently lags the live sizes by ~62 KB, so the endpoint returned
   events ending **~20 hours in the past**. The `recent` CLI subcommand
   defaults to `"physical"`, which is why the investigation's own event read
   saw current data. The service now passes `"physical"`, and an
   unrecognised `end_mode` raises instead of being ignored.

After both fixes, `/v1/events?limit=15` returns HTTP 200 in **7.3 s** with
events up to 56 seconds old — the last two entries being the read's own
`150 Autorizácia OK`.

**What this does not buy.** The hoped-for chain was: working event feed →
cheap tripwire on events 44/48 → a cached catalog read that can be *proven*
fresh, at ~150 ms and with no configuration-mode entry. That does not follow
on this hardware:

- The log volume is materialised only inside a session, exactly like
  `EXPORT.CFG`. Re-checked 17.5 hours after the investigation's own event
  read had filled it with 30,510 records: `FLEXILOG.TXT` scanned end to end
  was **all zeros again**. There is no session-free way to read events.
- So an event read costs a configuration-mode session of its own: **7.3 s**
  against **15.9 s** for a catalog pull. Polling the tripwire is roughly
  half the price of just pulling the catalog — worth having, but it is not
  free, and it does not avoid configuration mode.

The one genuinely free signal is the FAT directory: `FLEXILOG.OLD` and
`FLEXILOG.TXT` sizes advance live without any session (observed moving
across four sessionless reads), readable in ~0.25 s. Since a configuration
change always writes an event, *no growth since a known-good read* proves no
change occurred. It is one-directional and of limited use here — the panel
logs an ARC heartbeat every ~15 minutes, so the counter almost always
advances within a 900 s window and the proof rarely holds.

**Related, unfixed, and more serious.** `apply_import_sector` with the
default `stage_mode="filesystem"` also calls `mount_device`, so **user
writes through the deployed container fail the same way**. The
`sudo`-when-root fix removes the first wall; `CAP_SYS_ADMIN` remains, so
that path still needs either `JABLOTRON_PANEL_STAGE_MODE=direct` (an
existing mount-free staging mode that writes the sector by LBA) or the same
treatment the event path just received. Not changed here: it writes to the
panel, and that is not a change to make as a side effect of fixing a read.

**Observation worth a look.** During the seven minutes containing two
container restarts and two event reads, the panel logged seven
`119 Neplatná autorizace` events on the USB channel, sourced to
`Periféria 0: Ústredňa`, interleaved with our `150 Autorizácia OK`. The
39-day baseline is ~1/hour. No wrong code was ever submitted — the
configured code authorises successfully every time — so this looks like
session-churn handshake noise from the persistent-session reconnect rather
than anything this change introduced. Flagging it rather than concluding.
