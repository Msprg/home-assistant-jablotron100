# User-table write rules

The API server is the authority on what the panel will accept in a user
record. Clients submit a desired record; the server decides whether it is
legal and refuses with a machine-readable reason if it is not.

All of the rules below live in one place —
`src/jablotron_api/domain/user_validation.py` — and both write paths run
through it:

| Path | Entry point |
| --- | --- |
| HTTP `POST /v1/users`, `PATCH /v1/users/{id}` | `panel/runtime.py` → `services/user_manager.apply_upsert` |
| CLI `jablotron_user_tool add` / `edit` | `jablotron_user_tool.validate_preflight` |
| Demo runtime (`JABLOTRON_API_RUNTIME_MODE=demo`) | `panel/demo.py` |

Validation runs against a **fresh read** of the panel's user table, taken
under the panel lock immediately before the write, and against the record
that will actually be encoded into the import sector — not against the
request. A `PATCH` that omits `code` still writes the code carried over from
the panel, so that carried-over code is what gets checked.

## The duress/panic adjacency rule

**On this panel, entering a user's code with its last digit incremented mod
10 triggers a silent panic alarm.**

```
1483 -> 1484
1489 -> 1480
```

So a code that is another user's panic code must never be assigned. That
user would trip a silent alarm every time they legitimately unlock the door,
and by construction nobody would notice.

The rule is enforced **symmetrically**. For any two distinct codes `X` and
`Y` in the user table:

```
panic(X) != Y   and   panic(Y) != X   and   X != Y
```

where `panic(C)` is `C` with its last digit replaced by
`(last_digit + 1) % 10`.

Checking only one direction is the obvious bug here: whether a collision is
found would depend on which user was created first, so half the collisions
would get through. Both directions are checked, against the whole table.

The arithmetic rewrites the last *character* of the code string rather than
doing modular arithmetic on the number, so it holds for whatever
`code_length` the panel reports — 4, 6 or 8 — with no length constant in the
implementation.

### Consequence: at most 5 codes per prefix

Because adjacent last digits are forbidden in both directions, codes sharing
a prefix can only use non-adjacent last digits:

```
1480  1482  1484  1486  1488     <- all five coexist
1481  1483  1485  1487  1489     <- each collides with two of the above
```

**A prefix therefore supports at most 5 codes, not 10.** This is the rule
working as intended, not a defect in the implementation. Provisioning tools
that allocate codes sequentially within a prefix will hit it immediately;
allocate by stepping two, or vary the prefix.

## Code format

The PIN written into a user slot must be digits of the panel's own
installation-wide `code_length` (4, 6 or 8), read from the exported
`main_config` and resolved by `domain/codes.resolve_code_format`.

- The user slot stores the **bare PIN**. Even on a panel configured for
  prefixed codes, the `<user_id>*` part is typed at the keypad and must not
  be written into the record, so `validate_user_table_code` rejects it.
- If `code_length` cannot be established at all, the write is **refused**
  (`code_length_unknown`) rather than validated against a guessed length.
- If the length was inferred from the server's own authorisation code rather
  than read from `main_config` — the panel accepted that code, so its length
  is evidence rather than a guess — the write proceeds and the server logs
  that the length did not come from the panel.

## The other rules

| Reason | Meaning |
| --- | --- |
| `duplicate_code` | Another user already holds this code. |
| `duplicate_card` | Another user already holds this access card. |
| `card_repeated_in_request` | `card1` and `card2` are the same card. |
| `time_limited_group_requires_code` | A user in a time-limited group must have a code. |
| `name_too_long` | `name` exceeds 60 bytes of UTF-8. |
| `comment_too_long` | `comment` exceeds 60 bytes of UTF-8. |

## Field widths: 60 bytes, measured

`name` and `comment` are `CFG_MAX_TEXT_LEN` = 60 byte fields in the panel's
configuration schema. The limit is **bytes of UTF-8, not characters**: a
30-character comment of two-byte letters is full.

The usable length is **60, not 59**. This was measured, not read off the
schema: the live panel's own `EXPORT.CFG` carries a user whose comment is
exactly 60 bytes (58 characters, non-ASCII, decodes cleanly with no split
character), written through F-Link and read back through the export path.
So the field holds 60 bytes with no terminator inside it. The record encoder
(`import_cfg_tool.pack_msgpack`) does not clip; without these rules an
over-long value would reach the panel and be cut there, and the write would
then fail post-write verification as a mismatch with nothing in the response
saying why. The rule is applied to the record that will actually be encoded,
so it also catches a value carried over from an earlier write.

Both violations are reported together when both fields are over-long, and
neither is ever demoted to a warning: an over-long value cannot already be
on the panel, so it is always being introduced by the write being checked.
Messages give the byte count, never the value.

## Self-collisions are warnings, not refusals

An edit that leaves a user's own code or card unchanged is never refused for
colliding with itself, or for a collision that already exists on the panel
and is not being introduced by this write. Such a conflict is logged as a
warning and the write proceeds — otherwise a pre-existing collision (hand
provisioning, or a record written before these rules existed) would block
every unrelated edit, such as a rename.

The same demotion applies to the format rules: a write that carries an
unchanged code forward is not refused for that code's shape.

## Creating onto an occupied slot: `409 user_slot_occupied`

The panel's import is an upsert, so a `POST /v1/users` aimed at a slot that
already holds a user would silently overwrite that user. The server refuses
it instead, deciding on the **fresh read** taken under the panel lock (never
the cache: a stale "occupied" would refuse a slot F-Link has since freed,
and a stale "free" is exactly the overwrite this check prevents):

```json
{
  "detail": {
    "error": "user_slot_occupied",
    "user_id": 4,
    "message": "User slot 4 already holds a named user; pass replace=1 to overwrite it, or edit it with PATCH."
  }
}
```

A slot counts as occupied when its record has a non-empty name; the panel
keeps empty records for unused slots. `POST /v1/users?replace=1` overwrites
the occupant, and `PATCH` edits it. This is a `409` with `error` set — a
`409` whose `detail` is a plain string is still a panel or link failure (see
below).

The demo runtime (`JABLOTRON_API_RUNTIME_MODE=demo`) applies the same check.

## How a refusal is reported

`UserWriteRejected` (a `ValueError` subclass) carries every rule that fired,
each with a reason code, a human message, and the conflicting user IDs.

- **HTTP** — `400 Bad Request`:

  ```json
  {
    "detail": {
      "error": "user_write_rejected",
      "reason": "panic_code_collision",
      "message": "The submitted code is the silent-panic (duress) code of user(s) 7, so user 4 would raise a silent panic alarm on every legitimate use.",
      "violations": [
        {
          "reason": "panic_code_collision",
          "message": "...",
          "user_ids": [7]
        }
      ],
      "conflicting_user_ids": [7]
    }
  }
  ```

  A `400` with this body means *"that value is illegal, try another one"*. A
  `409` whose `detail` is a plain string means the panel or the link failed
  and the client should stop rather than retry (a `409` with
  `error: user_slot_occupied` is the occupied-slot refusal above, and is not
  a failure). A provisioning client must not confuse the two: retrying blind
  against a live alarm panel is not acceptable.

- **CLI** — the refusal is caught at the `main()` boundary and becomes the
  usual non-zero exit with `Preflight validation failed:` followed by one
  `[reason] message` line per rule.

Messages name the rule and the conflicting user IDs but **never quote a code
or card value**: they reach clients that hold `users:write` without the
sensitive read scope that unredacts codes, and they are written to the
server log.

## Testing

The rules are unit-tested offline against synthetic user tables in
`tests/test_user_write_validation.py` (arithmetic, both directions of the
panic rule, order independence, every `code_length`, the 5-per-prefix
ceiling, the 60-byte widths in bytes rather than characters) and the wiring
of both write paths and the occupied-slot refusal in
`tests/test_user_write_paths.py` and `tests/test_api_server.py`. Never test
these against the live panel: a wrong code write is exactly the failure mode
the rules exist to prevent.
