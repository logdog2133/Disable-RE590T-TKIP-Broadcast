# References

- TP-Link, [RE590T downloads and firmware](https://www.tp-link.com/us/support/download/re590t/).
  The page lists an UN-labeled v1 build; it was not flashed to the US unit.
- TP-Link, [regional firmware guidance](https://www.tp-link.com/us/document/14139/).
  TP-Link says US and EU firmware differ and should not be used on one another.
- TP-Link, [Weak Security and Privacy Warning on iOS](https://www.tp-link.com/us/support/faq/2943/).
  Its guidance identifies TKIP as incompatible with current recommended Wi-Fi
  security settings.
- TP-Link, [US home networking end-of-life list](https://static.tp-link.com/upload/manual/2026/202604/20260413/EOL%20List%20Home%20Networking%20-%20V7.1.pdf).
  The list records RE590T v1 US support ending on 2019-08-21.
- Microsoft, [`WlanScan`](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanscan).
  The call is asynchronous; the helper records beacon receive timestamps.
- Microsoft, [`WLAN_BSS_ENTRY`](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry).
  The structure carries the BSSID and the beacon/probe-response information
  elements used to inspect RSN group and pairwise cipher suites.

