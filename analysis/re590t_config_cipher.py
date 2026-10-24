"""Inspect RE590T 20171122 backup ciphers without displaying credentials.

Offline only: never contacts the device. Decoded data is not saved. By default
only reports numeric security fields. --candidate PATH writes a separate backup
with enabled WPA2-PSK station ciphers and their corresponding AP ciphers set to
AES. It preserves the first configuration block and NVRAM suffix verbatim.
No restore is performed. The candidate path is experimental until live verified.
"""
from pathlib import Path
from io import BytesIO
import argparse
import copy
import hashlib
import hmac
import json
import struct
import sys
import zlib

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "analysis-tools"))
from elftools.elf.elffile import ELFFile
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

FIRMWARE_PROGRAM_SHA256 = "0b524554247ea894749f028f30775649d9a80e056e39ab6e49d28369e3ae9369"
MAX_BACKUP = 0x50086
MAX_PLAIN = 0x20000
CIPHER_NAMES = {0: "Auto (TKIP+AES)", 1: "TKIP", 2: "AES"}


class FormatError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise FormatError(message)


def firmware_keys():
    raw = (BASE / "analysis" / "uclited.elf").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == FIRMWARE_PROGRAM_SHA256,
            "Unexpected firmware program; this helper supports only the inspected US 20171122 build.")
    elf = ELFFile(BytesIO(raw))
    symbols = {s.name: s for s in elf.get_section_by_name(".symtab").iter_symbols()}

    def take(name, size):
        addr = symbols[name]["st_value"]
        for segment in elf.iter_segments():
            if (segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= addr
                    and addr + size <= segment["p_vaddr"] + segment["p_filesz"]):
                offset = segment["p_offset"] + addr - segment["p_vaddr"]
                return raw[offset:offset + size]
        raise FormatError("Cannot map firmware format constant.")

    return take("desConfigKey", 8), take("md5ConfigKey", 16)


def des(data, key, encrypt=False):
    require(len(data) % 8 == 0, "Ciphertext length is not block aligned.")
    # A repeated DES key makes TripleDES equivalent to the firmware's DES-ECB.
    cipher = Cipher(TripleDES(key * 3), modes.ECB())
    operation = cipher.encryptor() if encrypt else cipher.decryptor()
    return operation.update(data) + operation.finalize()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON keys; refusing ambiguous configuration.")
        result[key] = value
    return result


def decode(raw, des_key, digest_key):
    require(0x1c < len(raw) <= MAX_BACKUP, "Unexpected backup size.")
    size1, size2, size_nvram = struct.unpack_from(">III", raw)
    require(0x1c + size1 + size2 + size_nvram == len(raw), "Outer length fields do not match.")
    require(hmac.compare_digest(raw[12:28], hashlib.md5(raw[28:]).digest()),
            "Outer backup checksum does not match.")
    start = 0x1c + size1
    inner = raw[start:start + size2]
    require(0x90 < size2 <= MAX_PLAIN, "Unexpected inner configuration size.")
    require(hmac.compare_digest(inner[:16], hashlib.md5(digest_key + inner[16:]).digest()),
            "Inner configuration checksum does not match.")
    require(b"RE590T" in inner[0x18:0x58], "Configuration is not identified as RE590T.")
    compressed = des(inner[0x90:], des_key)
    inflater = zlib.decompressobj()
    plain = inflater.decompress(compressed, MAX_PLAIN + 1)
    require(len(plain) <= MAX_PLAIN and inflater.eof and not inflater.unconsumed_tail,
            "Compressed configuration is invalid or exceeds the size limit.")
    require(all(byte == 0 for byte in inflater.unused_data), "Unexpected encryption padding.")
    require(plain.endswith(b"\0") and b"\0" not in plain[:-1], "Unexpected JSON terminator.")
    try:
        document = json.loads(plain[:-1].decode("utf-8"), object_pairs_hook=unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(FormatError("Invalid JSON number.")))
    except (ValueError, UnicodeError):
        raise FormatError("Configuration JSON could not be decoded.") from None
    return document, inner[:0x90], raw[28:start], raw[start + size2:]


def wifi_section(document):
    matches = []

    def visit(value, depth=0):
        require(depth <= 12, "Unexpectedly nested configuration.")
        if isinstance(value, dict):
            if "2G_Cfg" in value and "5G_Cfg" in value:
                matches.append(value)
            for child in value.values():
                visit(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth + 1)

    visit(document)
    require(len(matches) == 1, "Expected exactly one dual-band Wi-Fi configuration section.")
    section = matches[0]
    for band in ("2G_Cfg", "5G_Cfg"):
        require(isinstance(section[band], dict), "Unexpected band configuration type.")
        for role in ("staCfg", "apCfg"):
            entry = section[band].get(role)
            require(isinstance(entry, dict), "Expected station and AP configuration objects.")
            for key in ("wlanSecType", "psk_wpaVersion", "psk_wpaEncryption"):
                require(type(entry.get(key)) is int, "Security fields must be numeric.")
            require(entry["psk_wpaEncryption"] in CIPHER_NAMES, "Unrecognized cipher value.")
    return section


def cipher_report(section):
    rows = []
    for band in ("2G_Cfg", "5G_Cfg"):
        for role in ("staCfg", "apCfg"):
            entry = section[band][role]
            rows.append({"band": band, "role": role,
                         "security_type": entry["wlanSecType"],
                         "wpa_version": entry["psk_wpaVersion"],
                         "cipher": CIPHER_NAMES[entry["psk_wpaEncryption"]]})
    return rows


def candidate_bytes(document, header, first, suffix, des_key, digest_key):
    plain = json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode() + b"\0"
    require(len(plain) <= MAX_PLAIN, "Updated JSON exceeds the firmware size limit.")
    compressed = zlib.compress(plain)
    compressed += b"\0" * (-len(compressed) % 8)
    encrypted = des(compressed, des_key, encrypt=True)
    inner = digest_key + header[16:] + encrypted
    require(len(inner) < MAX_PLAIN, "Updated configuration exceeds its partition limit.")
    inner = hashlib.md5(inner).digest() + inner[16:]
    body = first + inner + suffix
    result = struct.pack(">III", len(first), len(inner), len(suffix)) + hashlib.md5(body).digest() + body
    require(len(result) <= MAX_BACKUP, "Updated backup exceeds the allowed size.")
    checked, checked_header, checked_first, checked_suffix = decode(result, des_key, digest_key)
    require(checked == document and checked_header[16:] == header[16:]
            and checked_first == first and checked_suffix == suffix, "Candidate integrity check failed.")
    return result


def changed_paths(before, after, prefix=()):
    if type(before) is not type(after):
        return [prefix]
    if isinstance(before, dict):
        require(before.keys() == after.keys(), "Candidate changed configuration keys.")
        return [path for key in before for path in changed_paths(before[key], after[key], prefix + (key,))]
    if isinstance(before, list):
        require(len(before) == len(after), "Candidate changed a configuration list length.")
        return [path for index, (a, b) in enumerate(zip(before, after))
                for path in changed_paths(a, b, prefix + (index,))]
    return [] if before == after else [prefix]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path)
    parser.add_argument("--candidate", type=Path, help="Prepare a separate experimental AES backup; never restores it")
    args = parser.parse_args()
    require(args.backup.is_file(), "Backup file was not found.")
    require(args.backup.stat().st_size <= MAX_BACKUP, "Backup exceeds the expected size limit.")
    if args.candidate:
        require(args.candidate.resolve() != args.backup.resolve(), "Cannot replace the source backup.")
        require(not args.candidate.exists(), "Candidate path already exists; no overwrite allowed.")
    des_key, digest_key = firmware_keys()
    raw = args.backup.read_bytes()
    document, header, first, suffix = decode(raw, des_key, digest_key)
    section = wifi_section(document)
    report = {"checksums_valid": True, "source_sha256": hashlib.sha256(raw).hexdigest(),
              "security": cipher_report(section), "device_contacted": False,
              "first_config_bytes": len(first)}
    if args.candidate:
        original_document = copy.deepcopy(document)
        # Refuse automatic edits unless BOTH backhauls are explicitly WPA2-PSK.
        # Cross-band inheritance and disabled bands require separate review.
        for band in ("2G_Cfg", "5G_Cfg"):
            sta = section[band]["staCfg"]
            ap = section[band]["apCfg"]
            require(sta.get("staBssEnabled") in (1, True), "A backhaul is disabled; manual inheritance review is required.")
            require(sta["wlanSecType"] == ap["wlanSecType"] == 1
                    and sta["psk_wpaVersion"] == ap["psk_wpaVersion"] == 2,
                    "Both bands must already be WPA2-PSK before candidate preparation.")
            sta["psk_wpaEncryption"] = 2
            ap["psk_wpaEncryption"] = 2
        differences = changed_paths(original_document, document)
        allowed_suffixes = {(band, role, "psk_wpaEncryption")
                            for band in ("2G_Cfg", "5G_Cfg") for role in ("staCfg", "apCfg")}
        require(len(differences) == 4 and {path[-3:] for path in differences} == allowed_suffixes,
                "Expected exactly four cipher-only changes; refusing any other difference.")
        candidate = candidate_bytes(document, header, first, suffix, des_key, digest_key)
        require(args.backup.read_bytes() == raw, "Source backup changed during processing.")
        # Exclusive creation keeps every existing file intact.
        with args.candidate.open("xb") as handle:
            handle.write(candidate)
        report["candidate_sha256"] = hashlib.sha256(candidate).hexdigest()
        report["candidate_security"] = cipher_report(section)
        report["changed_cipher_fields"] = len(differences)
        report["all_other_settings_preserved"] = True
        report["live_verification"] = "Not performed; do not restore without review."
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except FormatError as error:
        print("Stopped: " + str(error), file=sys.stderr)
        raise SystemExit(2)
    except Exception:
        # Never include exception values: malformed inputs may contain secrets.
        print("Stopped: unexpected local processing error; no device settings changed.", file=sys.stderr)
        raise SystemExit(3)

