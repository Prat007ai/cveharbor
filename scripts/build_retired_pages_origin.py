#!/usr/bin/env python3
"""Publish only a retirement notice at the former public Pages origin."""
from pathlib import Path

page='''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>CVEHarbor private development</title></head><body>
<h1>CVEHarbor is in private development</h1>
<p><a href="https://cveharbor.com/">Continue to the password-protected website</a>.</p>
</body></html>'''
target=Path('retired-pages-origin')
target.mkdir(exist_ok=True)
for name,content in {'index.html':page,'404.html':page,'robots.txt':'User-agent: *\nDisallow: /\n'}.items():
    (target/name).write_text(content)
if {p.name for p in target.iterdir()}!={'index.html','404.html','robots.txt'}:
    raise SystemExit('Refusing to publish unexpected files at the retired origin')
print('Retired-origin package contains only a notice and robots.txt; no application assets or data.')
