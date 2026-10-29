#!/usr/bin/env python3
"""Parse SQL Server CU/GDR entries from the official Microsoft servicing index.

If Microsoft changes its page or blocks collection, return no entries rather
than guessing versions, KB numbers or affected systems.
"""
import re
import urllib.request
from html.parser import HTMLParser

SOURCE = "https://support.microsoft.com/en-us/servicing/sql/kb321185-download-and-install-latest-updates"
SUPPORT = "https://support.microsoft.com/help/"
SUPPORTED_YEARS = {"2025": "17", "2022": "16", "2019": "15", "2017": "14"}
class MicrosoftSqlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.heading = ""
        self.current_heading = ""
        self.capturing_heading = False
        self.current_row = None
        self.current_cell = None
        self.rows = []
    def handle_starttag(self,tag,attrs):
        if tag in ("h2","h3","h4"):
            self.capturing_heading = True
            self.current_heading = ""
        if tag=="tr": self.current_row=[]
        if tag in ("td","th") and self.current_row is not None:self.current_cell=""
    def handle_data(self,data):
        if self.capturing_heading:self.current_heading+=data
        if self.current_cell is not None:self.current_cell+=data
    def handle_endtag(self,tag):
        if tag in ("h2","h3","h4") and self.capturing_heading:
            self.capturing_heading=False
            match=re.search(r"SQL Server\s+(20(?:25|22|19|17))",self.current_heading,re.I)
            if match:self.heading=match.group(1)
        if tag in ("td","th") and self.current_cell is not None:
            self.current_row.append(" ".join(self.current_cell.split()))
            self.current_cell=None
        if tag=="tr" and self.current_row is not None:
            self.rows.append((self.heading,self.current_row))
            self.current_row=None

def parse_microsoft_sql_updates(html):
    parser=MicrosoftSqlParser()
    parser.feed(html)
    results=[]
    seen=set()
    for year,cells in parser.rows:
        if year not in SUPPORTED_YEARS or len(cells)<4:continue
        version=cells[0].strip()
        if not re.fullmatch(r"\d{2}\.\d{1,4}\.\d{1,4}\.\d{1,4}",version):continue
        if version.split(".")[0]!=SUPPORTED_YEARS[year]:continue
        kb=next((re.search(r"KB\s*(\d{7,8})",c,re.I).group(1)
                 for c in cells if re.search(r"KB\s*\d{7,8}",c,re.I)),None)
        label=next((c for c in cells if re.search(r"\b(?:CU\d+|GDR)\b",c,re.I)),"")
        if not kb or not label or (year,version) in seen:continue
        seen.add((year,version))
        results.append({
            "slug":"mssqlserver","cycle":year,"version":version,
            "title":f"SQL Server {year} {label} (KB{kb})",
            "notes":f"Microsoft identifies this SQL Server {year} build as {label}, knowledge base article KB{kb}. Review the linked KB article for the fixes, security changes, known issues, and installation prerequisites.",
            "published":"","url":SUPPORT+kb,
            "security_mentioned":False,"source":"Microsoft SQL Server servicing history",
            "kb":f"KB{kb}","update_type":label
        })
    # One latest entry per distinct stream (CU / GDR) and supported version;
    # avoid sending all historical updates when a watch is first created.
    chosen=[]
    for year in SUPPORTED_YEARS:
        for kind in ("CU","GDR"):
            rows=[r for r in results if r["cycle"]==year and (\n                ("CU" in r["update_type"]) if kind=="CU" else r["update_type"].startswith("GDR"))]
            if rows:
                rows.sort(key=lambda r:tuple(map(int,r["version"].split("."))),reverse=True)
                chosen.append(rows[0])
    return chosen

def official_fix_summary(kb):
    url=SUPPORT+kb
    req=urllib.request.Request(url,headers={
        "User-Agent":"CVEHarbor-Patch-Collector/1.0","Accept":"text/html"})
    with urllib.request.urlopen(req,timeout=10) as response:
        text=response.read(900_000).decode("utf-8","replace")
    from html import unescape
    plain=unescape(re.sub(r"<[^>]+>"," ",re.sub(r"<(script|style)\\b[^>]*>[\\s\\S]*?</\\1>"," ",text,flags=re.I)))
    plain=" ".join(plain.split())
    patterns=[
        r"This update contains \\d+ fixes[^.]{0,240}\\.",
        r"This article describes Cumulative Update[^.]{0,240}\\.",
        r"This article describes (?:the )?security update[^.]{0,240}\\."
    ]
    for pattern in patterns:
        match=re.search(pattern,plain,re.I)
        if match:return match.group(0)[:400]
    return ""

def collect():
    req=urllib.request.Request(SOURCE,headers={
        "User-Agent":"CVEHarbor-Patch-Collector/1.0","Accept":"text/html"})
    with urllib.request.urlopen(req,timeout=20) as resp:
        markup=resp.read(2_000_000).decode("utf-8","replace")
    updates=parse_microsoft_sql_updates(markup)
    if not updates:
        raise ValueError("No current SQL CU/GDR table could be verified")
    for update in updates:
        try:
            verified=official_fix_summary(update["kb"][2:])
            if verified:
                update["notes"]+=" "+verified
        except Exception:
            pass
    return updates
