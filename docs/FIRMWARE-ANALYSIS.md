# Firmware and configuration findings

## Firmware examined

The installed image was the RE590T US v1.0 build
`1.0.0 Build 20171122 Rel. 62085`. The extracted components used for static
analysis were the stock HTTP server, wireless utility, and `uclited`. The
firmware image and extracted binaries are not included in this repository.

## Why WPA2 still advertised TKIP

Static analysis found this path in the installed build:

1. In `httpd:postFun`, choosing WPA2 sets the WPA version to 2 but stores cipher
   value `0` (Auto) for 2.4 GHz and 5 GHz. The stock extended-network page has no
   selector to override that value.
2. `uclited:opWifi_Sta_saveCfg` and `ucWifi_init` call
   `ucWifiApfollowSta`. The same-band path copies the station cipher into the
   local AP cipher field; the routine also has a cross-band inheritance path.
3. `wifi:_wifiNvramApCfg` maps the cipher values as follows:

   | Stored value | Wireless mode |
   | ---: | --- |
   | 0 | `tkip+aes` |
   | 1 | `tkip` |
   | 2 | `aes` |

4. In repeater mode, that local AP cipher value is written to the Broadcom
   `wl<band>.1_crypto` configuration. Thus the UI's WPA2 selection could still
   produce mixed TKIP/AES beacons.

The installed build already had an AES mode; no new encryption implementation
was needed. The change used the existing configuration field rather than
modifying the firmware executable.

## Configuration fields changed

The encrypted backup's decoded Wi-Fi configuration contains separate 2.4 and
5 GHz objects, each with `staCfg` (upstream station/backhaul) and `apCfg` (local
extended network). Each has `psk_wpaEncryption`.

The candidate changed exactly these four numeric fields:

```text
2G_Cfg.staCfg.psk_wpaEncryption: 0 -> 2
2G_Cfg.apCfg.psk_wpaEncryption:  0 -> 2
5G_Cfg.staCfg.psk_wpaEncryption: 0 -> 2
5G_Cfg.apCfg.psk_wpaEncryption:  0 -> 2
```

The helper refused to prepare a candidate unless both backhauls were enabled
WPA2-PSK. It preserved the other JSON values, the retained header bytes, the
outer config block, and the NVRAM suffix; then it regenerated and rechecked both
checksum layers. Candidate generation alone did not count as success—the device
was considered fixed only after fresh post-reboot beacons showed AES only.

## Paths considered but not used

- The hidden AP settings JSON handler targets a different local AP structure;
  static analysis did not establish it as a control for repeater broadcasts.
- SSH accepted a TCP connection but did not provide a shell or exec channel.
- The official support page exposed a newer UN-labeled build, but compatibility
  with this US unit was not established. TP-Link distinguishes regional firmware;
  no cross-region image was flashed.
- The firmware remains end-of-support. The cipher remediation does not patch
  unrelated firmware vulnerabilities.

