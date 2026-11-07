#!/usr/bin/env python3
import pathlib, re, sys
han = re.compile("[%s-%s]" % (chr(0x4E00), chr(0x9FFF)))
bad = []
for p in pathlib.Path('.').rglob('*'):
    if p.is_dir() or 'examples' in p.parts or '.git' in p.parts:
        continue
    if p.suffix not in {'.go', '.md', '.yml', '.yaml'}:
        continue
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        continue
    if han.search(text):
        bad.append(str(p))
if bad:
    print('Han characters in:', *bad, sep='\n  ', file=sys.stderr)
    sys.exit(1)
