#!/usr/bin/env python3
"""Compile a LuCI gettext .po catalog into the binary .lmo format.

This is a small, dependency-free equivalent of LuCI's `po2lmo` host tool,
producing a byte-identical archive for the catalogs used here:

    [string table (4-byte padded)] [16-byte index entries, sorted by key hash]
    [u32 BE string table length]

The key/val hashes use the "SuperFastHash" function from LuCI's lib/lmo.c.
"""

import struct
import sys


def sfh(data: bytes, init: int = 0) -> int:
    if not data:
        return 0
    h = init & 0xFFFFFFFF
    rem = len(data) & 3
    n = len(data) >> 2
    i = 0
    for _ in range(n):
        h = (h + int.from_bytes(data[i:i + 2], "little")) & 0xFFFFFFFF
        tmp = ((int.from_bytes(data[i + 2:i + 4], "little") << 11) ^ h) & 0xFFFFFFFF
        h = ((h << 16) ^ tmp) & 0xFFFFFFFF
        i += 4
        h = (h + (h >> 11)) & 0xFFFFFFFF
    if rem == 3:
        h = (h + int.from_bytes(data[i:i + 2], "little")) & 0xFFFFFFFF
        h ^= (h << 16) & 0xFFFFFFFF
        c = data[i + 2]
        h ^= ((c - 256 if c >= 128 else c) << 18) & 0xFFFFFFFF
        h = (h + (h >> 11)) & 0xFFFFFFFF
    elif rem == 2:
        h = (h + int.from_bytes(data[i:i + 2], "little")) & 0xFFFFFFFF
        h ^= (h << 11) & 0xFFFFFFFF
        h = (h + (h >> 17)) & 0xFFFFFFFF
    elif rem == 1:
        c = data[i]
        h = (h + (c - 256 if c >= 128 else c)) & 0xFFFFFFFF
        h ^= (h << 10) & 0xFFFFFFFF
        h = (h + (h >> 1)) & 0xFFFFFFFF
    h ^= (h << 3) & 0xFFFFFFFF
    h = (h + (h >> 5)) & 0xFFFFFFFF
    h ^= (h << 4) & 0xFFFFFFFF
    h = (h + (h >> 17)) & 0xFFFFFFFF
    h ^= (h << 25) & 0xFFFFFFFF
    h = (h + (h >> 6)) & 0xFFFFFFFF
    return h


def _string_after_quote(line: str) -> str:
    """Extract and unescape a quoted PO string (po2lmo rules)."""
    start = line.index('"') + 1
    out = []
    i = start
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt in ('"', "\\"):
                out.append(nxt)
            else:
                out.append(c)
                out.append(nxt)
            i += 2
            continue
        if c == '"':
            break
        out.append(c)
        i += 1
    return "".join(out)


def parse_po(text: str):
    msgs = []
    cur = None
    field = None

    def new_msg():
        return {"ctxt": "", "id": None, "idp": None, "val": {}, "plural": -1}

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("msgctxt "):
            if cur and (cur["id"] is not None or cur["val"]):
                msgs.append(cur)
            cur = new_msg()
            cur["ctxt"] = _string_after_quote(line)
            field = "ctxt"
        elif line.startswith("msgid_plural "):
            cur["idp"] = _string_after_quote(line)
            field = "idp"
        elif line.startswith("msgid "):
            if cur and (cur["id"] is not None or cur["val"]):
                msgs.append(cur)
            cur = new_msg()
            cur["id"] = _string_after_quote(line)
            field = "id"
        elif line.startswith("msgstr["):
            n = int(line[7:line.index("]")])
            cur["plural"] = n
            cur["val"][n] = _string_after_quote(line)
            field = ("val", n)
        elif line.startswith("msgstr "):
            cur["plural"] = 0
            cur["val"][0] = _string_after_quote(line)
            field = ("val", 0)
        elif line.startswith('"'):
            frag = _string_after_quote(line)
            if field == "ctxt":
                cur["ctxt"] += frag
            elif field == "id":
                cur["id"] += frag
            elif field == "idp":
                cur["idp"] = (cur["idp"] or "") + frag
            else:
                cur["val"][field[1]] += frag
    if cur:
        msgs.append(cur)
    return msgs


def compile_po(text: str) -> bytes:
    msgs = parse_po(text)
    table = bytearray()
    entries = []

    for m in msgs:
        if m["id"] and m["val"]:
            for i in range(0, m["plural"] + 1):
                if i not in m["val"]:
                    continue
                if m["ctxt"] and m["idp"]:
                    key = "%s\x01%s\x02%d" % (m["ctxt"], m["id"], i)
                elif m["ctxt"]:
                    key = "%s\x01%s" % (m["ctxt"], m["id"])
                elif m["idp"]:
                    key = "%s\x02%d" % (m["id"], i)
                else:
                    key = m["id"]

                val = m["val"][i]
                kb = key.encode()
                vb = val.encode()
                key_id = sfh(kb, len(kb))
                val_id = sfh(vb, len(vb))
                if key_id == val_id:
                    continue
                entries.append((key_id, m["plural"] + 1, len(table), len(vb)))
                table += vb
                table += b"\0" * ((-len(vb)) % 4)
        elif m["val"].get(0):
            # Header entry: keep the Plural-Forms formula, as po2lmo does.
            for line in m["val"][0].split("\\n"):
                if line.lower().startswith("plural-forms: "):
                    formula = line[len("Plural-Forms: "):]
                    fb = formula.encode()
                    entries.append((0, 0, len(table), len(fb)))
                    table += fb
                    table += b"\0" * ((-len(fb)) % 4)
                    break

    entries.sort(key=lambda e: e[0])
    out = bytearray(table)
    for key_id, val_id, off, length in entries:
        out += struct.pack(">IIII", key_id, val_id, off, length)
    if table:
        out += struct.pack(">I", len(table))
    return bytes(out)


def main(argv):
    if len(argv) != 3:
        print("usage: po2lmo.py <input.po> <output.lmo>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        text = f.read()
    data = compile_po(text)
    with open(argv[2], "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
