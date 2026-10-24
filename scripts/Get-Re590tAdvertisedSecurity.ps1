param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]] $NetworkNames,
    [switch] $RefreshScan
)

$ErrorActionPreference = 'Stop'

$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Re590tProbe
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Dot11Ssid
    {
        public UInt32 SsidLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Bytes;

        public Dot11Ssid(byte[] source)
        {
            SsidLength = (UInt32)source.Length;
            Bytes = new byte[32];
            Array.Copy(source, Bytes, source.Length);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WlanRateSet
    {
        public UInt32 Length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public UInt16[] Rates;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WlanBssEntry
    {
        public Dot11Ssid Ssid;
        public UInt32 PhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Bssid;
        public Int32 BssType;
        public Int32 PhyType;
        public Int32 Rssi;
        public UInt32 LinkQuality;
        public byte InRegDomain;
        public UInt16 BeaconPeriod;
        public UInt64 Timestamp;
        public UInt64 HostTimestamp;
        public UInt16 Capability;
        public UInt32 CenterFrequencyKHz;
        public WlanRateSet RateSet;
        public UInt32 IeOffset;
        public UInt32 IeSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WlanInterfaceInfo
    {
        public Guid Guid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        public Int32 State;
    }

    public static class WlanApi
    {
        [DllImport("wlanapi.dll")]
        public static extern UInt32 WlanOpenHandle(UInt32 version, IntPtr reserved, out UInt32 negotiatedVersion, out IntPtr clientHandle);

        [DllImport("wlanapi.dll")]
        public static extern UInt32 WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

        [DllImport("wlanapi.dll")]
        public static extern UInt32 WlanScan(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr ssid, IntPtr ieData, IntPtr reserved);

        [DllImport("wlanapi.dll")]
        public static extern UInt32 WlanGetNetworkBssList(
            IntPtr clientHandle,
            ref Guid interfaceGuid,
            ref Dot11Ssid ssid,
            Int32 bssType,
            [MarshalAs(UnmanagedType.Bool)] bool securityEnabled,
            IntPtr reserved,
            out IntPtr bssList);

        [DllImport("wlanapi.dll")]
        public static extern void WlanFreeMemory(IntPtr memory);

        [DllImport("wlanapi.dll")]
        public static extern UInt32 WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

        public static string[] ParseSecurityIes(byte[] data)
        {
            var results = new List<string>();
            int offset = 0;
            while (offset + 2 <= data.Length)
            {
                int id = data[offset];
                int length = data[offset + 1];
                int start = offset + 2;
                int end = start + length;
                if (end > data.Length)
                {
                    results.Add("Malformed information-element tail");
                    break;
                }

                if (id == 48)
                {
                    ParseSuiteSet("RSN", data, start, end, results);
                }
                else if (id == 221 && length >= 4 && data[start] == 0 && data[start + 1] == 0x50 && data[start + 2] == 0xF2 && data[start + 3] == 1)
                {
                    ParseSuiteSet("WPA", data, start + 4, end, results);
                }
                offset = end;
            }

            return results.ToArray();
        }

        private static UInt16 ReadUInt16(byte[] data, int offset)
        {
            return (UInt16)(data[offset] | (data[offset + 1] << 8));
        }

        private static string CipherSuite(byte[] data, int offset)
        {
            string oui = String.Format("{0:x2}:{1:x2}:{2:x2}", data[offset], data[offset + 1], data[offset + 2]);
            int type = data[offset + 3];
            string name = "type-" + type;
            if (oui == "00:0f:ac" || oui == "00:50:f2")
            {
                if (type == 1) name = "WEP-40";
                else if (type == 2) name = "TKIP";
                else if (type == 4) name = "CCMP-128 (AES)";
                else if (type == 5) name = "WEP-104";
                else if (type == 8) name = "GCMP-128";
                else if (type == 9) name = "GCMP-256";
                else if (type == 10) name = "CCMP-256";
            }
            return oui + "/" + name;
        }

        private static string AkmSuite(byte[] data, int offset)
        {
            string oui = String.Format("{0:x2}:{1:x2}:{2:x2}", data[offset], data[offset + 1], data[offset + 2]);
            int type = data[offset + 3];
            string name = "type-" + type;
            if (oui == "00:0f:ac" || oui == "00:50:f2")
            {
                if (type == 1) name = "802.1X";
                else if (type == 2) name = "PSK";
                else if (type == 3) name = "FT-802.1X";
                else if (type == 4) name = "FT-PSK";
                else if (type == 8) name = "SAE";
                else if (type == 9) name = "FT-SAE";
            }
            return oui + "/" + name;
        }

        private static void ParseSuiteSet(string label, byte[] data, int offset, int end, List<string> results)
        {
            if (offset + 2 > end)
            {
                results.Add(label + " truncated before version");
                return;
            }

            int version = ReadUInt16(data, offset);
            offset += 2;
            if (offset + 4 > end)
            {
                results.Add(label + " truncated before group cipher");
                return;
            }

            string group = CipherSuite(data, offset);
            offset += 4;
            if (offset + 2 > end)
            {
                results.Add(label + " truncated before pairwise count");
                return;
            }

            int pairwiseCount = ReadUInt16(data, offset);
            offset += 2;
            if (pairwiseCount > 64 || offset + 4 * pairwiseCount > end)
            {
                results.Add(label + " has a malformed pairwise list");
                return;
            }

            var pairwise = new List<string>();
            for (int i = 0; i < pairwiseCount; i++, offset += 4)
                pairwise.Add(CipherSuite(data, offset));

            if (offset + 2 > end)
            {
                results.Add(label + " version=" + version + " group=" + group + " pairwise=" + String.Join(",", pairwise) + "; AKM count absent");
                return;
            }

            int akmCount = ReadUInt16(data, offset);
            offset += 2;
            if (akmCount > 64 || offset + 4 * akmCount > end)
            {
                results.Add(label + " has a malformed AKM list");
                return;
            }

            var akm = new List<string>();
            for (int i = 0; i < akmCount; i++, offset += 4)
                akm.Add(AkmSuite(data, offset));

            results.Add(label + " version=" + version + " group=" + group + " pairwise=" + String.Join(",", pairwise) + " AKM=" + String.Join(",", akm));
        }
    }
}
'@

Add-Type -TypeDefinition $source
$entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][Re590tProbe.WlanBssEntry])
$ieOffsetField = [Runtime.InteropServices.Marshal]::OffsetOf([type][Re590tProbe.WlanBssEntry], 'IeOffset').ToInt32()
if ($entrySize -ne 360 -or $ieOffsetField -ne 352) {
    throw "Windows WLAN structure layout check failed (size=$entrySize, IE offset=$ieOffsetField). No network data was read."
}

$clientHandle = [IntPtr]::Zero
$interfaceList = [IntPtr]::Zero
$negotiatedVersion = [UInt32]0
$result = [Re590tProbe.WlanApi]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$negotiatedVersion, [ref]$clientHandle)
if ($result -ne 0) {
    throw "WlanOpenHandle failed with Windows error $result. Run this script from the Windows session connected to Wi-Fi."
}

try {
    $result = [Re590tProbe.WlanApi]::WlanEnumInterfaces($clientHandle, [IntPtr]::Zero, [ref]$interfaceList)
    if ($result -ne 0) { throw "WlanEnumInterfaces failed with Windows error $result." }

    $interfaceCount = [Runtime.InteropServices.Marshal]::ReadInt32($interfaceList, 0)
    $interfaceSize = [Runtime.InteropServices.Marshal]::SizeOf([type][Re590tProbe.WlanInterfaceInfo])
    for ($i = 0; $i -lt $interfaceCount; $i++) {
        $infoPointer = [IntPtr]::Add($interfaceList, 8 + ($i * $interfaceSize))
        $interfaceInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($infoPointer, [type][Re590tProbe.WlanInterfaceInfo])

        $scanRequestedAt = $null
        if ($RefreshScan) {
            $scanGuid = $interfaceInfo.Guid
            $scanRequestedAt = [DateTime]::UtcNow
            $scanResult = [Re590tProbe.WlanApi]::WlanScan($clientHandle, [ref]$scanGuid, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
            if ($scanResult -eq 0) {
                # WlanScan is asynchronous. This is a bounded wait, not a claim
                # of completion; per-beacon timestamps below establish freshness.
                Start-Sleep -Seconds 4
                Write-Output "Scan request accepted; waited 4 seconds. Confirm freshness from each beacon timestamp."
            } else {
                Write-Output "Scan request failed with Windows error $scanResult; returned entries may be cached."
            }
        }

        foreach ($targetSsid in $NetworkNames) {
            $ssidBytes = [Text.Encoding]::UTF8.GetBytes($targetSsid)
            if ($ssidBytes.Length -gt 32) { throw "SSID '$targetSsid' is longer than the Wi-Fi limit." }
            $ssidInput = [Re590tProbe.Dot11Ssid]::new($ssidBytes)

            $bssList = [IntPtr]::Zero
            $guid = $interfaceInfo.Guid
            $result = [Re590tProbe.WlanApi]::WlanGetNetworkBssList($clientHandle, [ref]$guid, [ref]$ssidInput, 1, $true, [IntPtr]::Zero, [ref]$bssList)
            if ($result -ne 0) {
                Write-Output "SSID=$targetSsid interface='$($interfaceInfo.Description)' query_error=$result"
                continue
            }

            try {
                $totalSize = [UInt32][Runtime.InteropServices.Marshal]::ReadInt32($bssList, 0)
                $bssCount = [UInt32][Runtime.InteropServices.Marshal]::ReadInt32($bssList, 4)
                if ($bssCount -eq 0) {
                    Write-Output "SSID=$targetSsid interface='$($interfaceInfo.Description)' BSS_count=0 (not in current scan cache)"
                    continue
                }

                if ($bssCount -gt 1) {
                    Write-Output "SSID=$targetSsid has $bssCount BSS entries; this script reports the first entry only."
                }

                $entryPointer = [IntPtr]::Add($bssList, 8)
                $entry = [Runtime.InteropServices.Marshal]::PtrToStructure($entryPointer, [type][Re590tProbe.WlanBssEntry])
                $availableBytes = [UInt64]$totalSize - 8
                $ieEnd = [UInt64]$entry.IeOffset + [UInt64]$entry.IeSize
                $ieValid = $entry.IeOffset -ge $entrySize -and $ieEnd -le $availableBytes -and $entry.IeSize -le 8192
                $actualSsid = [Text.Encoding]::UTF8.GetString($entry.Ssid.Bytes, 0, [int]$entry.Ssid.SsidLength)
                $bssid = ($entry.Bssid | ForEach-Object { $_.ToString('x2') }) -join ':'
                $band = if ($entry.CenterFrequencyKHz -lt 3000000) { '2.4 GHz' } else { '5 GHz' }
                Write-Output "SSID=$actualSsid BSSID=$bssid band=$band RSSI=$($entry.Rssi)dBm IE_valid=$ieValid"
                if ($RefreshScan) {
                    if ($scanResult -ne 0 -or $null -eq $scanRequestedAt) {
                        Write-Output '  Scan was not accepted; beacon freshness is unverified.'
                    } else {
                        try {
                            $seenAt = [DateTime]::FromFileTimeUtc([Int64]$entry.HostTimestamp)
                            $ageSeconds = [Math]::Round(([DateTime]::UtcNow - $seenAt).TotalSeconds, 2)
                            $receivedAfterRequest = $seenAt -ge $scanRequestedAt
                            Write-Output "  Beacon_received_UTC=$($seenAt.ToString('o')) age_seconds=$ageSeconds received_after_scan_request=$receivedAfterRequest"
                        } catch {
                            Write-Output '  Beacon timestamp invalid; freshness is unverified.'
                        }
                    }
                }

                if (-not $ieValid) {
                    Write-Output '  Information-element bounds were invalid; no IE bytes were parsed.'
                    continue
                }

                $ieData = New-Object byte[] ([int]$entry.IeSize)
                [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($entryPointer, [int]$entry.IeOffset), $ieData, 0, $ieData.Length)
                $security = [Re590tProbe.WlanApi]::ParseSecurityIes($ieData)
                if ($security.Length -eq 0) {
                    Write-Output '  No WPA or RSN security information element was present in the returned BSS data.'
                } else {
                    foreach ($line in $security) { Write-Output "  $line" }
                }
            }
            finally {
                [Re590tProbe.WlanApi]::WlanFreeMemory($bssList)
            }
        }
    }
}
finally {
    if ($interfaceList -ne [IntPtr]::Zero) { [Re590tProbe.WlanApi]::WlanFreeMemory($interfaceList) }
    [void][Re590tProbe.WlanApi]::WlanCloseHandle($clientHandle, [IntPtr]::Zero)
}

