#!/usr/bin/env python3
"""Decode a base64 nTSecurityDescriptor into human-readable form.

Turns the raw impacket dump (raw-byte GUIDs/SIDs, integer access masks, bare
flag values) into named rights, resolved trustees and schema object names.
"""
import re
import uuid
import base64
import argparse
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

# Security-descriptor control flags (SR_SECURITY_DESCRIPTOR['Control'])
SD_CONTROL_BITS = [
    (0x0001, "OWNER_DEFAULTED"),    (0x0002, "GROUP_DEFAULTED"),
    (0x0004, "DACL_PRESENT"),       (0x0008, "DACL_DEFAULTED"),
    (0x0010, "SACL_PRESENT"),       (0x0020, "SACL_DEFAULTED"),
    (0x0100, "DACL_AUTO_INHERIT_REQ"), (0x0200, "SACL_AUTO_INHERIT_REQ"),
    (0x0400, "DACL_AUTO_INHERITED"),   (0x0800, "SACL_AUTO_INHERITED"),
    (0x1000, "DACL_PROTECTED"),     (0x2000, "SACL_PROTECTED"),
    (0x4000, "RM_CONTROL_VALID"),   (0x8000, "SELF_RELATIVE"),
]

# ACE header flags (inheritance / audit)
ACE_FLAG_BITS = [
    (0x01, "OBJECT_INHERIT_ACE"),       (0x02, "CONTAINER_INHERIT_ACE"),
    (0x04, "NO_PROPAGATE_INHERIT_ACE"), (0x08, "INHERIT_ONLY_ACE"),
    (0x10, "INHERITED_ACE"),
    (0x40, "SUCCESSFUL_ACCESS_ACE_FLAG"), (0x80, "FAILED_ACCESS_ACE_FLAG"),
]

# Object-ACE flags (which of the two GUIDs are present)
OBJECT_ACE_FLAG_BITS = [
    (0x01, "ACE_OBJECT_TYPE_PRESENT"),
    (0x02, "ACE_INHERITED_OBJECT_TYPE_PRESENT"),
]

# Access-mask bits.  High word = standard/generic rights, low word = AD-specific.
ACCESS_MASK_BITS = [
    (0x80000000, "GENERIC_READ"),    (0x40000000, "GENERIC_WRITE"),
    (0x20000000, "GENERIC_EXECUTE"), (0x10000000, "GENERIC_ALL"),
    (0x02000000, "MAXIMUM_ALLOWED"), (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x00100000, "SYNCHRONIZE"),     (0x00080000, "WRITE_OWNER"),
    (0x00040000, "WRITE_DACL"),      (0x00020000, "READ_CONTROL"),
    (0x00010000, "DELETE"),
    (0x00000100, "DS_CONTROL_ACCESS"),  # extended right
    (0x00000080, "DS_LIST_OBJECT"),     (0x00000040, "DS_DELETE_TREE"),
    (0x00000020, "DS_WRITE_PROP"),      (0x00000010, "DS_READ_PROP"),
    (0x00000008, "DS_SELF"),            # validated write
    (0x00000004, "DS_LIST_CHILDREN"),
    (0x00000002, "DS_DELETE_CHILD"),    (0x00000001, "DS_CREATE_CHILD"),
]

FULL_CONTROL = 0x000F01FF  # all standard + all AD-specific rights

# Map AceType byte -> short verb for the heading.
ACE_TYPE_VERB = {
    0x00: "ALLOW", 0x01: "DENY", 0x02: "AUDIT", 0x03: "ALARM",
    0x05: "ALLOW", 0x06: "DENY", 0x07: "AUDIT", 0x08: "ALARM",
    0x09: "ALLOW", 0x0A: "DENY", 0x0B: "AUDIT", 0x0C: "ALARM",
    0x11: "LABEL",
}
ALLOW_TYPES = {0x00, 0x05, 0x09}  # types that actually grant access

# Well-known directory-service GUIDs (extended rights, validated writes,
# property sets, attributes and classes).  Curated to the security-relevant set;
# anything not listed is printed as a bare GUID.
WELL_KNOWN_GUIDS = {
    # --- Extended rights: replication (DCSync) ---
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    # --- Extended rights: passwords / account ---
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "00000000-0000-0000-0000-000000000000": "All / GenericAll (no object restriction)",
    # --- Validated writes (paired with DS_SELF) ---
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership (write member)",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-DNS-Host-Name",
    "80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
    # --- Property sets ---
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions [property set]",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon [property set]",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Group-Membership [property set]",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information [property set]",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information [property set]",
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information [property set]",
    "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information [property set]",
    # --- Attributes (object type on read/write-property) ---
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "ms-DS-KeyCredentialLink (Shadow Credentials)",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD)",
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "gPLink",
    "f30e3bbf-9ff0-11d1-b603-0000f80367c1": "gPOptions",
    # --- Object classes (object type on create/delete-child) ---
    "bf967aba-0de6-11d0-a285-00aa003049e2": "User [class]",
    "bf967a86-0de6-11d0-a285-00aa003049e2": "Computer [class]",
    "bf967a9c-0de6-11d0-a285-00aa003049e2": "Group [class]",
    "bf967aa8-0de6-11d0-a285-00aa003049e2": "Print-Queue [class]",
    "5cb41ed0-0e4c-11d0-a286-00aa003049e2": "Contact [class]",
    "4828cc14-1437-45bc-9b07-ad6f015e5f28": "inetOrgPerson [class]",
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1": "Group-Policy-Container [class]",
}

# Well-known SIDs (universal).
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Null", "S-1-1-0": "Everyone", "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group",
    "S-1-5-2": "Network", "S-1-5-4": "Interactive", "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous", "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self", "S-1-5-11": "Authenticated Users",
    "S-1-5-15": "This Organization", "S-1-5-18": "Local System (SYSTEM)",
    "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicator",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users", "S-1-5-32-557": "Incoming Forest Trust Builders",
    "S-1-5-32-573": "Event Log Readers", "S-1-5-32-574": "Certificate Service DCOM Access",
    "S-1-5-32-580": "Remote Management Users",
}

# Well-known RIDs on a domain SID (S-1-5-21-<domain>-<RID>).
DOMAIN_RIDS = {
    "498": "Enterprise Read-only Domain Controllers", "500": "Administrator",
    "501": "Guest", "502": "krbtgt", "512": "Domain Admins",
    "513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers",
    "516": "Domain Controllers", "517": "Cert Publishers", "518": "Schema Admins",
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers", "522": "Cloneable Domain Controllers",
    "525": "Protected Users", "526": "Key Admins", "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}

# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_bits(value, table):
    """Return the names of every flag in `table` set in `value`."""
    return [name for bit, name in table if value & bit]


def format_guid(raw):
    """16 raw little-endian GUID bytes -> canonical GUID string ('' if empty)."""
    if not raw:
        return ""
    return str(uuid.UUID(bytes_le=bytes(raw)))


def name_guid(raw):
    """GUID bytes -> 'guid (Friendly-Name)' or just the GUID if unknown."""
    guid = format_guid(raw)
    if not guid:
        return ""
    friendly = WELL_KNOWN_GUIDS.get(guid.lower())
    return f"{guid} ({friendly})" if friendly else guid


def name_sid(sid):
    """Annotate a canonical SID string with a well-known principal name."""
    if sid in WELL_KNOWN_SIDS:
        return f"{sid} ({WELL_KNOWN_SIDS[sid]})"
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid in DOMAIN_RIDS:
            return f"{sid} ({DOMAIN_RIDS[rid]})"
    return sid


# RIDs at or above this are admin-created principals (users/groups/computers);
# everything below it in a domain is a reserved/well-known builtin.
RID_THRESHOLD = 1000


def is_expected_trustee(sid, ignore=()):
    """True for default/builtin principals you'd expect in any stock ACL.

    'Interesting' (returns False) means an admin-created domain principal: an
    S-1-5-21-<domain>-<RID> with RID >= RID_THRESHOLD that isn't a known default
    group. This is what --interesting-only keeps; everything else is hidden.
    Note foreign-domain principals match too (still S-1-5-21-...), which is what
    you want — a foreign SID with rights is a finding, not noise.
    """
    if sid is None:
        return False                  # no trustee SID -> can't classify, so show it
    if sid in ignore:
        return True
    if sid in WELL_KNOWN_SIDS:
        return True
    if sid.startswith("S-1-5-32-"):
        return True                   # BUILTIN local groups (named or not)
    if sid.startswith("S-1-5-21-"):   # a domain SID
        rid = sid.rsplit("-", 1)[-1]
        if rid in DOMAIN_RIDS:
            return True
        try:
            return int(rid) < RID_THRESHOLD
        except ValueError:
            return False
    return True                       # other well-known authorities (S-1-1, S-1-3, S-1-5-<low>, ...)


def ace_trustee_sid(ace):
    """Canonical trustee SID of an ACE, or None if it carries no SID."""
    inner = ace['Ace']
    if 'Sid' in getattr(inner, 'fields', {}):
        return inner['Sid'].formatCanonical()
    return None


def describe_mask(mask):
    """Access mask int -> compact name list (collapsing full control)."""
    if (mask & FULL_CONTROL) == FULL_CONTROL:
        extra = decode_bits(mask & ~FULL_CONTROL, ACCESS_MASK_BITS)
        return ["FULL_CONTROL"] + extra
    names = decode_bits(mask, ACCESS_MASK_BITS)
    return names or [f"0x{mask:08x}"]


def attack_hints(verb, mask, obj_guid):
    """Heuristic red-team notes for the abusable rights on an ALLOW ACE."""
    if verb != "ALLOW":
        return []
    hints, g = [], (obj_guid or "").lower()
    if (mask & FULL_CONTROL) == FULL_CONTROL or mask & 0x10000000:
        hints.append("GenericAll / Full Control -> full object takeover")
    if mask & 0x00040000:
        hints.append("WriteDACL -> grant yourself any right over this object")
    if mask & 0x00080000:
        hints.append("WriteOwner -> set owner, then rewrite the DACL")
    if mask & 0x40000000:
        hints.append("GenericWrite -> write attributes (SPN/RBCD/scripts)")
    if mask & 0x00000100:  # DS_CONTROL_ACCESS — meaning depends on the object GUID
        if g in ("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                 "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"):
            hints.append("DCSync replication right -> dump domain hashes")
        elif g == "00299570-246d-11d0-a768-00aa006e0529":
            hints.append("ForceChangePassword -> reset this account's password")
        elif not g:
            hints.append("All extended rights")
    if mask & 0x00000008 and g == "bf9679c0-0de6-11d0-a285-00aa003049e2":
        hints.append("Self-Membership -> add yourself to this group")
    if mask & 0x00000020:  # DS_WRITE_PROP on a sensitive attribute
        if g == "5b47d60f-6090-40b2-9f37-2a4de88f3063":
            hints.append("Write msDS-KeyCredentialLink -> Shadow Credentials (PKINIT)")
        elif g == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79":
            hints.append("Write msDS-AllowedToActOnBehalfOf -> Resource-Based Constrained Delegation")
    return hints


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_ace(index, ace):
    inner = ace['Ace']
    fields = getattr(inner, 'fields', {})
    verb = ACE_TYPE_VERB.get(ace['AceType'], "?")
    type_name = ace['TypeName']

    lines = [f"[{index:02d}] {verb:5s} {type_name}"]

    if 'Sid' in fields:
        lines.append(f"       Trustee : {name_sid(inner['Sid'].formatCanonical())}")

    if 'Mask' in fields:
        mask = inner['Mask']['Mask']
        lines.append(f"       Access  : {', '.join(describe_mask(mask))}  (0x{mask:08x})")
    else:
        mask = 0

    obj_guid = ""
    if 'ObjectType' in fields and inner['ObjectType']:
        obj_guid = format_guid(inner['ObjectType'])
        lines.append(f"       Object  : {name_guid(inner['ObjectType'])}")
    if 'InheritedObjectType' in fields and inner['InheritedObjectType']:
        lines.append(f"       Applies : inherited by {name_guid(inner['InheritedObjectType'])}")

    flags = decode_bits(ace['AceFlags'], ACE_FLAG_BITS)
    if flags:
        lines.append(f"       AceFlags: {', '.join(flags)}")
    if 'Flags' in fields:
        oflags = decode_bits(inner['Flags'], OBJECT_ACE_FLAG_BITS)
        if oflags:
            lines.append(f"       ObjFlags: {', '.join(oflags)}")

    for hint in attack_hints(verb, mask, obj_guid):
        lines.append(f"       [!]     {hint}")

    return "\n".join(lines)


def annotate_principal(sid, ignore=()):
    """name_sid() plus a marker when the principal is non-default (e.g. custom owner)."""
    label = name_sid(sid)
    if not is_expected_trustee(sid, ignore):
        label += "   [!] non-default principal"
    return label


def render_sd(sd, interesting_only=False, ignore=()):
    """Render one parsed SD to a list of lines. Also returns `interesting`:
    True when a -i view surfaces anything (non-default owner/group, or any ACE)."""
    lines, interesting = [], False

    def principal(value):
        nonlocal interesting
        if not value:
            return "(none)"
        sid = value.formatCanonical()
        if not is_expected_trustee(sid, ignore):
            interesting = True
        return annotate_principal(sid, ignore)

    lines.append(f"Owner   : {principal(sd['OwnerSid'])}")
    lines.append(f"Group   : {principal(sd['GroupSid'])}")
    lines.append(f"Control : {', '.join(decode_bits(sd['Control'], SD_CONTROL_BITS))}  (0x{sd['Control']:04x})")

    for acl_name in ('Dacl', 'Sacl'):
        acl = sd[acl_name]
        if not acl:
            continue
        shown, hidden = [], 0
        for i, ace in enumerate(acl['Data']):
            # Keep the real ACE index i so positions match the unfiltered output.
            if interesting_only and is_expected_trustee(ace_trustee_sid(ace), ignore):
                hidden += 1
                continue
            shown.append((i, ace))
        if shown:
            interesting = True
        header = f"{acl_name} ({acl['AceCount']} ACEs"
        if interesting_only:
            header += f", {len(shown)} shown / {hidden} default hidden"
        lines.append(f"\n=== {header}) ===")
        if interesting_only and not shown:
            lines.append("    (no non-default trustees)")
        lines.extend(render_ace(i, ace) for i, ace in shown)

    return lines, interesting


# nTSecurityDescriptor blobs serialise to base64 starting "AQA" (Revision=0x01,
# Sbz1=0x00) plus a 4th char encoding the Control low byte:
#   "AQAE" -> 0x04  DACL present, no SACL        (default LDAP read)
#   "AQAU" -> 0x14  DACL present + SACL present   (queried with the SACL flag)
# Anchor on either prefix as a cheap pre-filter, then *validate* every candidate
# below. Add more prefixes here if you ever meet defaulted-flag variants.
SD_PREFIXES = ("AQAE", "AQAU")
SD_BLOB_RE = re.compile(r'(?:%s)[A-Za-z0-9+/]*={0,2}' % "|".join(SD_PREFIXES))
_MIN_BLOB_CHARS = 28  # a header-only (20-byte) SD is ~28 b64 chars; skip shorter noise


def scan_blobs(text):
    """Yield (match, sd, error) for each AQAE/AQAU-anchored candidate in `text`.
    `match` is the regex Match (its position lets us look up context); `sd` is a
    parsed descriptor on success, otherwise `error` explains the skip."""
    for match in SD_BLOB_RE.finditer(text):
        blob = match.group(0)
        if len(blob) < _MIN_BLOB_CHARS:
            continue
        if len(blob) % 4:
            yield match, None, "incomplete base64 (length not a multiple of 4 — split in the source?)"
            continue
        try:
            data = base64.b64decode(blob, validate=True)
        except Exception as exc:
            yield match, None, f"base64 error: {exc}"
            continue
        try:
            yield match, SR_SECURITY_DESCRIPTOR(data=data), None
        except Exception as exc:
            yield match, None, f"not a security descriptor: {exc}"


def _shorten(blob, head=48, tail=12):
    return blob if len(blob) <= head + tail + 1 else f"{blob[:head]}…{blob[-tail:]}"


# Object identity lives outside the SD, in the surrounding text. To stay
# format-agnostic we never parse the file structure — we just look near the blob
# for the one universal LDAP attribute that carries the object's name: its DN.
# The KEY ("distinguishedName"/"dn") and the DN VALUE are byte-identical across
# ldapsearch, LDIF and BloodHound/bofhound JSON, so this one regex labels them
# all; when it matches nothing, the blob prints exactly as before.
DN_LABEL_RE = re.compile(
    r'(?i)(?:"?\bdistinguishedname\b"?|"?\bdn\b"?)\s*[:=]\s*"?'
    r'((?:CN|OU|DC)=[^,\r\n"]+(?:,(?:CN|OU|DC)=[^,\r\n"]+)*)')
_LABEL_WINDOW = 6000  # chars to look around a blob for its distinguishedName


def nearest_dn(text, start, lo):
    """Best-effort object DN: the closest `distinguishedName`/`dn` value that
    *precedes* the blob within its own record (after the previous blob `lo`,
    capped by the window). member/objectCategory DNs are ignored because we key
    on the attribute, and we never guess forward — no preceding DN, no label."""
    region = text[max(lo, start - _LABEL_WINDOW):start]
    found = DN_LABEL_RE.findall(region)
    return found[-1].strip() if found else None


def scan_file(path, interesting_only, ignore):
    with open(path, "r", errors="replace") as handle:
        text = handle.read()

    results = list(scan_blobs(text))           # materialise so we can see neighbours
    spans = [m.span() for m, _, _ in results]  # blob positions delimit records

    valid = printed = boring = bad = 0
    for idx, (match, sd, err) in enumerate(results):
        blob = match.group(0)
        if err:
            bad += 1
            print(f"[!] skipped SD candidate — {err}\n    {_shorten(blob)}\n")
            continue
        valid += 1
        body, interesting = render_sd(sd, interesting_only, ignore)
        if interesting_only and not interesting:
            boring += 1            # all-default; counted in the summary, not printed
            continue
        printed += 1
        # Confine the DN search to this blob's own record (after the previous
        # blob) so a label can't be borrowed from a neighbouring object.
        lo = spans[idx - 1][1] if idx > 0 else 0
        label = nearest_dn(text, match.start(), lo)
        print("=" * 72)
        if label:
            print(label)           # which object this SD belongs to (when discoverable)
        print("\n".join(body))
        print()

    parts = [f"{valid} valid SD(s)"]
    if interesting_only:
        parts.append(f"{printed} with non-default trustees, {boring} all-default (hidden)")
    if bad:
        parts.append(f"{bad} SD candidate(s) failed validation")
    print("=" * 72)
    print("Scan summary: " + "; ".join(parts) + ".")


def main():
    parser = argparse.ArgumentParser(
        description="Decode base64 nTSecurityDescriptor(s) into human-readable form.")
    parser.add_argument("sd_b64", nargs="?",
                        help="a single base64 nTSecurityDescriptor (omit when using --file)")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="scan a text file (e.g. an LDAP dump) for nTSecurityDescriptor "
                             "blobs (AQAE/AQAU...), validate each, and parse it")
    parser.add_argument(
        "-i", "--interesting-only", action="store_true",
        help="hide ACEs whose trustee is a default/builtin principal (well-known SIDs, "
             "BUILTIN groups, domain RIDs < %d); show only admin-created principals. "
             "With --file, all-default descriptors are summarised rather than printed." % RID_THRESHOLD)
    parser.add_argument(
        "--ignore-sid", action="append", default=[], metavar="SID",
        help="also treat this exact SID as default/expected (repeatable)")
    args = parser.parse_args()
    ignore = set(args.ignore_sid)

    if args.file:
        scan_file(args.file, args.interesting_only, ignore)
    elif args.sd_b64:
        sd = SR_SECURITY_DESCRIPTOR(data=base64.b64decode(args.sd_b64.strip()))
        print("\n".join(render_sd(sd, args.interesting_only, ignore)[0]))
    else:
        parser.error("provide a base64 blob, or --file PATH to scan")


if __name__ == "__main__":
    main()

