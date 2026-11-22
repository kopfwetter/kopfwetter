# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Erzeugt die englische index.html aus der deutschen: Textstücke zwischen Tags und einige Attribute
werden über i18n/en-html.json ersetzt (Schlüssel = Text mit zusammengefassten Leerzeichen).
Die gleiche Logik steckt in mobile/scripts/build-www.mjs für die Apps."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ATTRS = ("placeholder", "aria-label", "title", "alt", "content")


def load(lang: str) -> dict:
    path = os.path.join(HERE, "i18n", f"{lang}-html.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def translate_html(src: str, table: dict, lang: str) -> tuple[str, list[str]]:
    """Gibt (übersetztes HTML, nicht übersetzte deutsche Textstücke) zurück."""
    out, missing, skip = [], [], 0
    for part in re.split(r"(<[^>]+>)", src):
        if part.startswith("<"):
            low = part.lower()
            if re.match(r"<(script|style)\b", low):
                skip += 1
            elif re.match(r"</(script|style)\b", low):
                skip -= 1

            def attr(m):
                v = m.group(2)
                return f'{m.group(1)}="{table[v]}"' if v in table else m.group(0)
            part = re.sub(r'\b(%s)="([^"]*)"' % "|".join(ATTRS), attr, part)
            if low.startswith("<html"):
                part = re.sub(r'lang="[^"]*"', f'lang="{lang}"', part)
            out.append(part)
            continue
        key = " ".join(part.split())
        if skip or not key:
            out.append(part)
        elif key in table:
            lead = part[: len(part) - len(part.lstrip())]
            trail = part[len(part.rstrip()):]
            out.append(lead + table[key] + trail)
        else:
            if re.search(r"[a-zäöüß]{3,}", key):
                missing.append(key)
            out.append(part)
    return "".join(out), missing
