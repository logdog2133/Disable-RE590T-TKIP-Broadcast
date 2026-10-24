# Verification record

All identifiers below are sanitized. No serial number, password, SSID, BSSID,
private IP, raw backup, or raw configuration candidate is stored here.

## After the successful restore and reboot

A Windows WLAN scan was explicitly requested. Each listed beacon timestamp was
newer than the scan request:

| Band | RSN group cipher | RSN pairwise cipher(s) | Beacon age | Result |
| --- | --- | --- | ---: | --- |
| 5 GHz | CCMP-128 (AES) | CCMP-128 (AES) only | 2.56 s | Fresh; no TKIP |
| 2.4 GHz | CCMP-128 (AES) | CCMP-128 (AES) only | 3.61 s | Fresh; no TKIP |

Both were WPA2-PSK. This was direct beacon evidence after the extender reboot,
not just the cipher negotiated by a client. The user then reported that the
iPhone “Weak Security” warning was gone and confirmed Internet access through
the extender.

The available backup from the first restore attempt still showed Auto; no fresh
backup from the successful second restore was captured. The live post-reboot
beacons therefore provide the verification of the effective setting.

## After switching to Copy Host SSID

The user reported that the extender continued working. A later scan returned
multiple BSS entries sharing the copied SSID, and the existing helper reports
only the first BSS for a name. That fresh entry was 2.4 GHz and remained
CCMP/AES-only. At the same time, the Windows client was connected through the
extender's 5 GHz radio using WPA2-Personal and CCMP/AES. These facts support
continued function, but the 5 GHz beacon IE was not independently re-read after
the copied-SSID change. Both band beacons had been directly verified AES-only
immediately after the successful restore and before that naming change.

## How to read the evidence

- `Cipher: CCMP` from `netsh wlan show interfaces` identifies one negotiated
  client link. It does not prove what the AP advertises for group or pairwise
  ciphers.
- A beacon RSN element that lists CCMP for group and pairwise and omits TKIP is
  the evidence used here for AES-only advertisement.
- A timestamp received after `WlanScan` was requested demonstrates a fresh
  returned beacon. `WlanScan` is asynchronous; a fixed wait alone does not
  prove the scan completed.
- The iPhone warning disappearing and user-confirmed Internet access establish
  the user-visible and functional outcome, not the general security of the
  end-of-support firmware.

