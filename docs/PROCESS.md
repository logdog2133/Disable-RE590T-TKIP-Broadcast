# End-to-end process

This is the sequence that led from the iPhone warning to a working AES-only
broadcast on one RE590T(US) v1.0. Credentials and unique network identifiers are
omitted.

## 1. Preserve the required function and establish the exact device

The requirement was to keep the extender operating on the home network; turning
it off, replacing it, or moving it to a guest network would not meet the goal.
The admin page identified the unit as RE590T v1.0 running
`1.0.0 Build 20171122 Rel. 62085`. The extended-network UI had no cipher control.

The extender was reset and configured again with both host bands connected using
WPA2-PSK. Temporary distinct extended SSIDs made it possible to identify each
radio during the initial beacon checks. No credentials are recorded here.

## 2. Separate negotiated client security from advertised beacon security

`netsh wlan show interfaces` showed WPA2-Personal with CCMP on a tested client
link. This proved that this client negotiated AES; it did not prove that the
extender advertised AES alone.

A read-only Windows WLAN scan parsed the RSN information elements in fresh
beacons for the two distinct extended SSIDs. Before remediation, both bands
advertised group TKIP and pairwise CCMP plus TKIP. This explained why a client
could connect with CCMP while iOS still warned about weak security.

The repeatable scan command, after substituting the local SSIDs, is:

```powershell
.\scripts\Get-Re590tAdvertisedSecurity.ps1 `
  -NetworkNames @('your-5-GHz-SSID', 'your-2.4-SSID') `
  -RefreshScan
```

`WlanScan` is asynchronous. The helper requests a scan, waits briefly, and
reports each returned beacon's receive time and whether it arrived after the
request. Treat the timestamp—not the wait duration—as the freshness evidence.

## 3. Trace the stock firmware behavior

The RE590T stock UI allowed WPA2-PSK selection but wrote the cipher as Auto.
Static analysis of the exact installed firmware showed that Auto maps to
`tkip+aes` in the Broadcom wireless configuration path. The detailed functions,
field names, and caveats are in [`FIRMWARE-ANALYSIS.md`](FIRMWARE-ANALYSIS.md).

An alternative hidden web handler was examined and rejected: it applied to a
different AP-specific settings structure and did not establish a safe control
for the active repeater broadcasts. No SSH shell or supported custom firmware
path was available, and no firmware was flashed.

## 4. Prepare an offline AES-only configuration candidate

With the user's permission, a fresh extender configuration backup was inspected
locally. The decoder verified both checksum layers, validated the RE590T format,
and printed only the four cipher settings and integrity metadata; it did not
print the decoded JSON, SSIDs, or passwords.

All four relevant values were Auto (`0`). The candidate builder changed only
the 2.4 and 5 GHz station/backhaul and local AP `psk_wpaEncryption` values from
`0` to `2` (AES). It verified that both backhauls were enabled WPA2-PSK, preserved
all other configuration and metadata, rebuilt the checksums, decoded the result
again, and created a new file without overwriting the original.

The source backup and candidate were kept local. The candidate contains the
existing saved credentials and must not be committed or shared.

## 5. Restore, recover, and repeat after the first attempt failed

The user selected the candidate manually in the extender's Backup & Restore UI
and approved the restore. The first attempt rebooted the extender, but the
backup saved afterward was byte-for-byte identical to the original and all four
cipher fields were still Auto. The reason the first attempt failed was not
established.

The user selected the same approved candidate again and restored it. After the
extender rebooted, the admin page returned and both radios were operating. A
fresh beacon scan then showed CCMP/AES only for both group and pairwise cipher
lists. The live scan, rather than the restore page response, was used to verify
the effective result.

## 6. Confirm the user-visible and functional outcome

The user reported that the iPhone warning disappeared and confirmed Internet
access through the extender. The user later selected “Copy Host SSID” and
reported that the extender continued working.

After the copied-SSID change, the scan helper found multiple BSS entries with
the same SSID but reports only the first entry. The latest scan directly showed
the 2.4 GHz beacon as AES-only; the connected 5 GHz client link negotiated
CCMP. The 5 GHz beacon was directly verified as AES-only after the restore but
before the SSID-copy change. See the verification record for this distinction.

## 7. What remains true after the fix

The fix addresses the specific mixed TKIP/AES broadcast and the warning. The
installed firmware is end-of-support and still has unrelated firmware risk. If
wireless host settings are saved again—such as during password rotation—repeat
the beacon check because the stock save path can write Auto again.

