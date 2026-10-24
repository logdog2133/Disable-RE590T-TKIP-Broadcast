# Disable RE590T TKIP Broadcast

This repository records the successful, device-specific remediation of mixed
TKIP/AES advertisements on a TP-Link RE590T(US) v1.0 range extender while
keeping its extender function online.

## Result

The stock UI offered WPA2-PSK but no cipher selector. Fresh beacon scans showed
that the extender advertised TKIP as its group cipher and as a pairwise option
alongside CCMP/AES on both bands. Windows client links negotiated CCMP, but that
alone did not establish that the beacons were AES-only.

Offline analysis found that the firmware's Auto cipher value maps to mixed
TKIP/AES mode. A locally prepared configuration candidate changed four cipher
fields (2.4 and 5 GHz station/backhaul and AP fields) from Auto to AES and
preserved the other decoded settings. The first restore attempt did not persist;
the same candidate was selected and restored again. After the extender rebooted,
fresh scans showed CCMP/AES only in both bands' group and pairwise cipher lists.

The user then reported that the phone's “Weak Security” warning was gone and
that Internet access worked through the extender. The user later switched to
copying the host SSID and reported that it still works. See
[`docs/VERIFICATION.md`](docs/VERIFICATION.md) for the exact evidence and the
remaining limit on the latest same-name scan.

## Start here

- [`docs/PROCESS.md`](docs/PROCESS.md) — the investigation and successful
  end-to-end steps, including the failed first restore.
- [`docs/FIRMWARE-ANALYSIS.md`](docs/FIRMWARE-ANALYSIS.md) — how the stock
  firmware turns Auto into mixed TKIP/AES and which configuration fields were
  changed.
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) — sanitized beacon and client
  evidence, with limitations.
- [`docs/REFERENCES.md`](docs/REFERENCES.md) — official vendor and API sources.
- [`scripts/Get-Re590tAdvertisedSecurity.ps1`](scripts/Get-Re590tAdvertisedSecurity.ps1)
  — Windows read-only beacon/RSN inspection helper.
- [`analysis/re590t_config_cipher.py`](analysis/re590t_config_cipher.py) —
  offline backup inspection and candidate builder for the exact firmware build.

## Use the local tools carefully

The Wi-Fi scan helper prints the SSID and BSSID it inspects. Supply the target
SSID locally and redact names and hardware addresses before sharing output:

```powershell
.\scripts\Get-Re590tAdvertisedSecurity.ps1 `
  -NetworkNames @('your-2.4-SSID', 'your-5-GHz-SSID') `
  -RefreshScan
```

It currently reports the first BSS returned for each SSID. If the router and
extender share a copied SSID, that name may map to multiple BSS entries; use
separate temporary names when checking each radio or use a scanner that reports
every BSS.

The configuration tool is offline. It requires the matching `uclited.elf`
extracted locally from the exact stock firmware and the Python packages
`pyelftools` and `cryptography`. It prints cipher/integrity metadata only, but
its input backup and generated candidate contain saved network credentials.
Never commit, upload, or share either file. The `.gitignore` excludes common
firmware, backup, capture, and log files; inspect `git status` before committing.

## Scope and safety

This resolves the observed TKIP broadcast behavior for the tested unit; it does
not make the old firmware broadly secure. The extender remains on the 2017
end-of-support build. No firmware image was flashed, and the newer UN-labeled
image was not applied to the US unit because region compatibility was not
established. Do not restore another unit's candidate or cross-flash firmware.

The successful configuration candidate is intentionally not included. Do not
publish device backups, candidates, raw scans, serial numbers, BSSIDs, SSIDs,
private IP addresses, or passwords.

