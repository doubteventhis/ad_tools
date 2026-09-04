#!/usr/bin/env python3
import sys

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate
UAC_FLAGS = {
    0x0000_0001: "SCRIPT",
    0x0000_0002: "ACCOUNTDISABLE",
    0x0000_0008: "HOMEDIR_REQUIRED",
    0x0000_0010: "LOCKOUT",
    0x0000_0020: "PASSWD_NOTREQD",
    0x0000_0040: "PASSWD_CANT_CHANGE",
    0x0000_0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0000_0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0000_0200: "NORMAL_ACCOUNT",
    0x0000_0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x0000_1000: "WORKSTATION_TRUST_ACCOUNT",
    0x0000_2000: "SERVER_TRUST_ACCOUNT",
    0x0001_0000: "DONT_EXPIRE_PASSWORD",
    0x0002_0000: "MNS_LOGON_ACCOUNT",
    0x0004_0000: "SMARTCARD_REQUIRED",
    0x0008_0000: "TRUSTED_FOR_DELEGATION",
    0x0010_0000: "NOT_DELEGATED",
    0x0020_0000: "USE_DES_KEY_ONLY",
    0x0040_0000: "DONT_REQUIRE_PREAUTH",
    0x0080_0000: "PASSWORD_EXPIRED",
    0x0100_0000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x0200_0000: "NO_AUTH_DATA_REQUIRED",
    0x0400_0000: "PARTIAL_SECRETS_ACCOUNT",
}

ALL_KNOWN_BITS = 0
for bit in UAC_FLAGS:
    ALL_KNOWN_BITS |= bit


def parse_uac_value(raw: str) -> int:
    # accepts decimal or hex
    raw = raw.strip()
    if raw.lower().startswith("0x"):
        return int(raw, 16)
    return int(raw)


def decode_flags(uac: int) -> list[str]:
    active = []
    for bit, name in sorted(UAC_FLAGS.items()):
        if uac & bit:
            active.append(name)
    return active


def find_unknown_bits(uac: int) -> int:
    return uac & ~ALL_KNOWN_BITS


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <UAC_VALUE>")
        print(f"  Example: {sys.argv[0]} 66048")
        print(f"  Example: {sys.argv[0]} 0x10200")
        sys.exit(1)

    try:
        uac = parse_uac_value(sys.argv[1])
    except ValueError:
        print("[!] provide a UAC value (decimal or hex)")
        sys.exit(1)

    print(f"UserAccountControl: {uac} (0x{uac:08X})")

    flags = decode_flags(uac)
    if flags:
        for flag in flags:
            print(f"  [+] {flag}")
    else:
        print("  No known flags matched.")

    unknown = find_unknown_bits(uac)
    if unknown:
        print(f"\n  [!] Unknown bits set: 0x{unknown:08X}")


if __name__ == "__main__":
    main()
