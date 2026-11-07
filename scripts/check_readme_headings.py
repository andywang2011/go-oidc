#!/usr/bin/env python3
import pathlib, re, sys
text = pathlib.Path('README.md').read_text(encoding='utf-8')
heads = re.findall(r'^## (.+)$', text, re.M)
want = ['Install', 'Quick start', 'Examples', 'License']
if heads != want:
    print(f'README ## headings must be exactly {want}, got {heads}', file=sys.stderr)
    sys.exit(1)
