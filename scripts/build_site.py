#!/usr/bin/env python3
"""Publish only the public static assets, never credentials, sample seeds or .git."""
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'public'
if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir()
for name in ('index.html','styles.css','app.js','data.js','CNAME','robots.txt'):
    shutil.copy2(ROOT/name, OUT/name)
(OUT/'.nojekyll').touch()
print('Built public site:', [x.name for x in OUT.iterdir()])
