#!/usr/bin/env python3
"""
Read a dumped IDS baseline table file (e.g. ids_base.tbl, produced by
IDS_DUMP_BASELINE_CC) and print its contents in human-readable form.

Works on Windows or Linux with a stock Python 3 install - no dependencies
beyond the standard library.

Usage:
    python read_ids_baseline.py path/to/ids_base.tbl

File layout (all cFE table dump files use this same two-header format):
    [0:64]     CFE_FS_Header_t      - standard cFE file header, big-endian
    [64:116]   CFE_TBL_File_Hdr_t   - table-specific header, big-endian
    [116:]     raw IDS_BaselineTbl_t bytes, NATIVE little-endian byte order
               and the host compiler's natural struct alignment (cFE does not
               byte-swap or re-pack the table payload itself, only the two
               headers above it).
"""
import ctypes as ct
import struct
import sys

CFE_FS_HEADER_SIZE = 64
CFE_TBL_HEADER_SIZE = 52
CFE_FS_CONTENT_ID = 0x63464531  # 'cFE1'

IDS_MAX_TRACKED_APPS = 32
IDS_MAX_TRACKED_MIDS = 128
IDS_MAX_EVENTS_PER_APP = 16
CFE_MISSION_MAX_API_LEN = 20


class IDS_AppProfile(ct.Structure):
    _fields_ = [
        ("Recorded", ct.c_bool),
        ("Enabled", ct.c_bool),
        ("AppName", ct.c_char * CFE_MISSION_MAX_API_LEN),
        ("KnownEventIds", ct.c_uint16 * IDS_MAX_EVENTS_PER_APP),
        ("KnownEventCount", ct.c_uint8),
        ("EventCount", ct.c_uint32),
        ("LastEventTimeMs", ct.c_uint64),
        ("IntervalEwmaMs", ct.c_double),
    ]


class IDS_MidProfile(ct.Structure):
    _fields_ = [
        ("Recorded", ct.c_bool),
        ("MsgId", ct.c_uint32),  # CFE_SB_MsgId_t is {uint32 Value}
        ("MsgCount", ct.c_uint32),
        ("LastSeenTimeMs", ct.c_uint64),
        ("IntervalEwmaMs", ct.c_double),
    ]


class IDS_BaselineTbl(ct.Structure):
    _fields_ = [
        ("AppProfile", IDS_AppProfile * IDS_MAX_TRACKED_APPS),
        ("MidProfile", IDS_MidProfile * IDS_MAX_TRACKED_MIDS),
    ]


def parse_fs_header(data):
    fields = struct.unpack_from(">8I32s", data, 0)
    (content_type, subtype, length, sc_id, cpu_id, app_id, t_sec, t_subsec, desc) = fields
    return {
        "ContentType": content_type,
        "SubType": subtype,
        "Length": length,
        "SpacecraftID": sc_id,
        "ProcessorID": cpu_id,
        "ApplicationID": app_id,
        "TimeSeconds": t_sec,
        "TimeSubSeconds": t_subsec,
        "Description": desc.split(b"\x00", 1)[0].decode(errors="replace"),
    }


def parse_tbl_header(data):
    reserved, offset, num_bytes, name = struct.unpack_from(">3I40s", data, CFE_FS_HEADER_SIZE)
    return {
        "Reserved": reserved,
        "Offset": offset,
        "NumBytes": num_bytes,
        "TableName": name.split(b"\x00", 1)[0].decode(errors="replace"),
    }


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path/to/ids_base.tbl")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    if len(data) < CFE_FS_HEADER_SIZE + CFE_TBL_HEADER_SIZE:
        print(f"File too small ({len(data)} bytes) to be a valid cFE table dump.")
        sys.exit(1)

    fs_hdr = parse_fs_header(data)
    if fs_hdr["ContentType"] != CFE_FS_CONTENT_ID:
        print(f"WARNING: ContentType 0x{fs_hdr['ContentType']:08X} != expected 0x{CFE_FS_CONTENT_ID:08X} "
              f"('cFE1') - this may not be a cFE table dump file.")

    tbl_hdr = parse_tbl_header(data)

    print("=== cFE File Header ===")
    print(f"  Description  : {fs_hdr['Description']}")
    print(f"  SpacecraftID : {fs_hdr['SpacecraftID']}")
    print(f"  ProcessorID  : {fs_hdr['ProcessorID']}")
    print(f"  Timestamp    : {fs_hdr['TimeSeconds']}.{fs_hdr['TimeSubSeconds']} (mission time)")
    print()
    print("=== cFE Table Header ===")
    print(f"  TableName    : {tbl_hdr['TableName']}")
    print(f"  NumBytes     : {tbl_hdr['NumBytes']}")
    print()

    payload_start = CFE_FS_HEADER_SIZE + CFE_TBL_HEADER_SIZE
    payload = data[payload_start:payload_start + ct.sizeof(IDS_BaselineTbl)]
    if len(payload) != ct.sizeof(IDS_BaselineTbl):
        print(f"WARNING: expected {ct.sizeof(IDS_BaselineTbl)} bytes of table payload, "
              f"found {len(payload)}. IDS_MAX_TRACKED_APPS/MIDS in this script may not match "
              f"the build that produced this file (check ids_platform_cfg.h).")

    tbl = IDS_BaselineTbl.from_buffer_copy(payload.ljust(ct.sizeof(IDS_BaselineTbl), b"\x00"))

    print("=== Learned App Profiles ===")
    app_count = 0
    for p in tbl.AppProfile:
        if not p.Recorded:
            continue
        app_count += 1
        known_ids = list(p.KnownEventIds)[: p.KnownEventCount]
        print(f"  [{p.AppName.decode(errors='replace'):<20}] "
              f"enabled={bool(p.Enabled)!s:<5} events_seen={p.EventCount:<8} "
              f"avg_interval_ms={p.IntervalEwmaMs:.1f} "
              f"last_event_ms={p.LastEventTimeMs}")
        print(f"      known_event_ids ({p.KnownEventCount}): {known_ids}")
    if app_count == 0:
        print("  (none recorded)")

    print()
    print("=== Learned MID Profiles ===")
    mid_count = 0
    for m in tbl.MidProfile:
        if not m.Recorded:
            continue
        mid_count += 1
        print(f"  MID=0x{m.MsgId:04X}  msg_count={m.MsgCount:<8} "
              f"avg_interval_ms={m.IntervalEwmaMs:.1f} last_seen_ms={m.LastSeenTimeMs}")
    if mid_count == 0:
        print("  (none recorded)")

    print()
    print(f"Total: {app_count} app profile(s), {mid_count} MID profile(s) "
          f"(capacity {IDS_MAX_TRACKED_APPS}/{IDS_MAX_TRACKED_MIDS})")


if __name__ == "__main__":
    main()
