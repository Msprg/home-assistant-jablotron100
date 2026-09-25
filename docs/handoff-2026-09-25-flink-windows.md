# Handoff: capture an F-Link user write on the Windows PC (2026-09-25)

For a Claude agent running on the Windows PC that has F-Link installed and
can reach the JA-107K panel over USB. Everything below is a request for
measurements. Nothing here asks you to change anything on the panel beyond
one throwaway user in one slot, which you delete again at the end.

## Why you are doing this

A Linux host normally talks to this panel over USB: a HID interface for
the protocol, and a USB mass-storage interface with two volumes,
`FLEXI_CFG` (100 MiB, read/write, holds `EXPORT.CFG` and `IMPORT.CFG`) and
`FLEXI_LOG` (1.1 GiB, read-only). The Linux tooling changes users by
writing an encoded sector into `IMPORT.CFG` through the FAT driver, then
asking the panel over HID to accept the import.

Today the panel refuses every SCSI `Write(10)` to `FLEXI_CFG` from Linux:
sense key *Hardware Error*, on the `IMPORT.CFG` data sector (LBA 2083) and
on the directory sector (LBA 27) alike. Four attempts, from a container,
from the host, and after a USB replug, all identical. The user table was
never changed.

The owner reports that F-Link connects fine. What nobody knows yet is
whether F-Link can **write** to this panel today, and if it can, what its
USB write sequence looks like compared with ours. You are going to find
out both.

## What to deliver

Put everything in one folder, zip it, and hand the zip to the owner.
Do not upload it anywhere: the capture contains the panel's full
configuration export, which includes user codes.

1. `capture.pcapng`: a USBPcap capture of the panel's USB traffic covering
   F-Link's connect, one user save, one user delete, and disconnect.
2. `writes.txt`: the SCSI write commands from that capture with their
   LBAs and completion status (commands below).
3. `timeline.txt`: local wall-clock times (to the second) of: capture
   start, F-Link connect, first save clicked, first save finished, delete
   save clicked, delete save finished, F-Link disconnect, capture stop.
   Plus the exact text of any error or warning F-Link showed.
4. `environment.txt`: F-Link version, the panel firmware version and
   serial as F-Link shows them, which connection channel F-Link used
   (USB, LAN, or cloud), Windows version, the drive letter Windows gave
   `FLEXI_CFG` and the output of the disk checks below.
5. `flink-logs/`: copies of F-Link's communication logs from
   `%APPDATA%\Jablotron\FLink\` (files named `comm.log*.htm`) that were
   modified during the test. They are obfuscated; the Linux side has a
   decoder. Copy the whole folder if in doubt.
6. `procmon.csv` (optional but valuable): a Process Monitor trace filtered
   to the `FLEXI_CFG` drive letter, showing F-Link's file operations on
   `IMPORT.CFG` and their results.
7. `windows-events.txt`: System event log entries from the disk, storage
   and USB sources during the test window (command below).

## Safety envelope

- The only permitted change is user slot **96**: name `Test96`, comment
  `handoff-test`, nothing else. No code, no card, no phone, no section or
  PG rights, no other user, no section, no PG, no settings.
- If slot 96 is already occupied when F-Link shows the user list, stop and
  report that instead.
- If Windows offers to "scan and fix" the `FLEXI_CFG` drive when the panel
  is plugged in, decline. The volume's dirty flag is one of the things we
  want to observe, not repair.
- If F-Link offers a firmware update, decline.
- Do not run `chkdsk`, `format`, `diskpart clean`, or any write to the
  `FLEXI_CFG` drive from Windows yourself. F-Link is the only writer.

## Before you plug in the cable

The panel is plugged into the Linux host right now. The owner will move
the cable. Before that happens, the Linux side stops its API container so
the panel is not mid-session when it disconnects. Ask the owner to confirm
the Linux side is stopped before the cable moves.

## Step 1: tools

Check what is installed; install what is missing (Wireshark's installer
includes USBPcap as an option; Process Monitor is a Sysinternals download).

```powershell
Get-Command tshark, USBPcapCMD -ErrorAction SilentlyContinue | Format-Table Name, Source
Test-Path "C:\Program Files\USBPcap\USBPcapCMD.exe"
Test-Path "C:\Program Files\Wireshark\tshark.exe"
```

USBPcap needs an elevated prompt. Run the rest from an Administrator
PowerShell.

## Step 2: identify the panel and its root hub

After the cable is plugged in:

```powershell
Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_16D6&PID_0008' } | Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
Get-Volume | Where-Object FileSystemLabel -in 'FLEXI_CFG','FLEXI_LOG' | Format-Table DriveLetter, FileSystemLabel, FileSystem, Size, HealthStatus
& "C:\Program Files\USBPcap\USBPcapCMD.exe"
```

`USBPcapCMD.exe` lists the root hubs (`\\.\USBPcap1`, `\\.\USBPcap2`, ...)
with the devices under each. Find the one that lists `JA-100 Flexi` or the
VID/PID pair, and note its number. Press Ctrl+C rather than starting a
capture from this interactive prompt.

Record the drive letter of `FLEXI_CFG` as `X:` below (substitute the real
letter everywhere).

## Step 3: disk checks before F-Link runs

Read-only checks. Save the output into `environment.txt`.

```powershell
fsutil dirty query X:
fsutil fsinfo volumeinfo X:
Get-Disk | Where-Object FriendlyName -match 'Flexi' | Format-List Number, FriendlyName, IsReadOnly, IsOffline, HealthStatus, OperationalStatus
Get-ChildItem X:\ | Format-Table Name, Length, LastWriteTime
```

`fsutil dirty query` is the point: we expect "Volume - X: is Dirty",
because the last Linux attempt could not write the directory sector that
would have cleared it.

## Step 4: start the capture, then run F-Link

Start USBPcap on the root hub you identified (replace `N`), in its own
window, before launching F-Link:

```powershell
& "C:\Program Files\USBPcap\USBPcapCMD.exe" -d \\.\USBPcapN -o capture.pcapng -A
```

Note the time. If you run Process Monitor, start it now too with a filter
`Path begins with X:\` and let it run.

Then, in F-Link:

1. Connect to the panel over **USB**. Note the time and the channel F-Link
   reports. If F-Link connects over LAN or cloud instead, stop and note
   it: that path does not exercise USB mass storage and would not answer
   the question. Read F-Link's panel info page: firmware version, serial.
2. Open the users table. Confirm slot 96 is empty.
3. Enter name `Test96` and comment `handoff-test` in slot 96. Nothing
   else.
4. Save to the panel. Note the time you click and the time F-Link reports
   completion. Copy the exact text of any dialog.
5. Re-read the users from the panel (F-Link's read/refresh) and confirm
   slot 96 shows the new user. Note the time.
6. Delete user 96 and save again. Note both times and any dialog.
7. Re-read and confirm slot 96 is empty again.
8. Disconnect F-Link. Note the time.

Stop the capture (Ctrl+C in its window) and Process Monitor. Note the
time.

Repeat the disk checks from step 3 and append them to `environment.txt`
labelled "after".

## Step 5: extract the write commands from the capture

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcapng -Y "scsi_sbc.opcode == 0x2a" -T fields -e frame.number -e frame.time -e usb.device_address -e scsi.lba -e scsi.sbc.len > writes-cbw.txt
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcapng -Y "usbms.dCSWStatus" -T fields -e frame.number -e frame.time -e usb.device_address -e usbms.dCSWStatus -e usbms.dCSWTag > csw.txt
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcapng -Y "scsi.sense.key" -T fields -e frame.number -e frame.time -e scsi.sense.key -e scsi.sense.asc -e scsi.sense.ascq > sense.txt
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcapng -Y "scsi_sbc.opcode == 0x2a || scsi_sbc.opcode == 0x28 || usbms.dCSWStatus" -V > ms-verbose.txt
```

If a field name is rejected, find the right one with
`tshark -G fields | findstr /i usbms` and `... | findstr /i scsi.lba`,
and note the substitution.

Combine the first three into `writes.txt`: one line per `Write(10)`, with
its LBA, transfer length, and the status of the CSW that answered it
(0 = passed, 1 = failed), and any sense data that followed. What we need
to know, in order of importance:

- Did any `Write(10)` complete with status 0? Which LBAs?
- Did F-Link write LBA 2083 and LBA 27, or different sectors?
- Did F-Link issue anything **before** its first write that we do not:
  `Mode Sense`, `Test Unit Ready`, `Prevent/Allow Medium Removal`, a
  `Request Sense`, a vendor-specific opcode, a HID exchange right before
  the write? List the SCSI opcodes in the 10 seconds before the first
  `Write(10)`, in order:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcapng -Y "scsi.opcode" -T fields -e frame.number -e frame.time -e scsi.opcode -e scsi.lba > all-scsi.txt
```

## Step 6: Windows-side evidence

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-1)} | Where-Object { $_.ProviderName -match 'disk|storahci|USBSTOR|UASPStor|partmgr|volmgr|Ntfs|fastfat|Kernel-PnP' } | Format-List TimeCreated, Id, ProviderName, Message > windows-events.txt
```

Copy `%APPDATA%\Jablotron\FLink\comm.log*.htm` files with a modification
time inside the test window into `flink-logs\`.

If Process Monitor ran, save its trace filtered to `X:\IMPORT.CFG` as CSV.

## Step 7: report

Write `timeline.txt` and `environment.txt` in plain text. State outcomes
plainly: "first save succeeded, F-Link showed no dialog, slot 96 read back
with the new user" or "first save failed with dialog text ...". If you
could not complete a step, say which and why. Do not summarise the
capture beyond `writes.txt`; the Linux side will read it.

Then hand the cable back: tell the owner the test is done, so the panel
can be plugged back into the Linux host and the API container restarted.

## What the Linux side will do with it

- Compare F-Link's `Write(10)` sequence with ours (same LBAs, same
  preceding commands, same CSW results).
- Decode the F-Link comm logs with `f_link_comm_log_tool.py`.
- Pull the panel's event log and check for event `48` (configuration
  change) at the two save times, and re-read the user table to confirm
  slot 96 is empty.

If F-Link's writes were refused too, the panel is refusing all USB
writes today and the investigation moves off this codebase. If they
succeeded, the difference in the capture is the next thing to fix.
