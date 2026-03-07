# Reverse Engineering Workspace

This tree is for Jablotron protocol-reversing artifacts that should not live in the repo root.

Directory layout:

- `captures/usb/f_link/`
  Existing and future USB captures from F-Link sessions.
- `captures/usb/live/`
  USB captures from direct CLI or live probing against the panel.
- `captures/derived/`
  Derived text artifacts from captures, such as TSV exports or filtered packet listings.
- `fdb/before/`
  `.fdb` files saved before a single controlled change.
- `fdb/after/`
  `.fdb` files saved after the same controlled change.
- `fdb/diffs/`
  Any notes, binary diffs, or extracted comparisons derived from `.fdb` pairs.
- `exports/`
  Config exports, backups, or other files written by F-Link.
- `traces/procmon/`
  Procmon traces or similar Windows-side file activity captures around F-Link.
- `notes/`
  Short text notes describing exact actions, timestamps, and test values used in a capture.

Recommended capture naming:

- `YYYY-MM-DD_read-users-only.pcapng`
- `YYYY-MM-DD_add-user-U17TEST.pcapng`
- `YYYY-MM-DD_rename-user-07-to-U17TEST.pcapng`
- `YYYY-MM-DD_change-code-user-07.pcapng`
- `YYYY-MM-DD_delete-user-07.pcapng`

For high-value datasets, keep a matching note file in `notes/` with:

- panel state before the run
- exact F-Link actions taken
- usernames / codes / user numbers used
- absolute timestamps if available
