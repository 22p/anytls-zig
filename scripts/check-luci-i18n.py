#!/usr/bin/env python3
"""Check that every LuCI UI string is present in the pot and translated.

Run from the repository root:
    scripts/check-luci-i18n.py
"""
import pathlib
import re
import sys

APP = pathlib.Path("openwrt/luci/luci-app-anytls-zig")
JS = APP / "htdocs/luci-static/resources/view/anytls-zig/settings.js"
POT = APP / "po/templates/anytls-zig.pot"
PO = APP / "po/zh_Hans/anytls-zig.po"


def msgids_from_js(text):
    out = []
    for m in re.finditer(r"_\(\s*'([^']*)'", text):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


def pairs(path):
    text = path.read_text(encoding="utf-8")
    result = {}
    for m in re.finditer(r'msgid "((?:[^"\\]|\\.)*)"\s*\nmsgstr "((?:[^"\\]|\\.)*)"', text):
        result[m.group(1).replace('\\"', '"').replace("\\\\", "\\")] = m.group(2)
    return result


def main():
    ids = msgids_from_js(JS.read_text(encoding="utf-8"))
    pot = pairs(POT)
    po = pairs(PO)
    errors = []
    for s in ids:
        if s not in pot:
            errors.append(f"missing from pot: {s!r}")
        if s not in po:
            errors.append(f"missing from zh_Hans: {s!r}")
        elif not po[s]:
            errors.append(f"untranslated in zh_Hans: {s!r}")
    for s in errors:
        print(s, file=sys.stderr)
    print(f"{len(ids)} strings, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
