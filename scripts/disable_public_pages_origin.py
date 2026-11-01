#!/usr/bin/env python3
"""Retire the old public Pages origin only after the protected frontend is verified."""
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from deploy_site_gate import CONFIG, probe


def main():
    config=json.loads(CONFIG.read_text())
    if config["vars"].get("SITE_GATE_ENABLED")=="false":return
    probe("https://cveharbor.com",True,config["vars"]["SITE_GATE_USERNAME"],os.environ.get("SITE_GATE_PASSWORD",""))
    if os.environ.get("GITHUB_REPOSITORY","").lower()!="prat007ai/cveharbor":
        raise RuntimeError("Refusing to change Pages settings outside the CVEHarbor repository")
    token=os.environ.get("GITHUB_TOKEN")
    if not token:raise RuntimeError("A Pages-write GitHub credential is required to close the old public origin")
    url="https://api.github.com/repos/Prat007ai/cveharbor/pages"
    headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=25) as response:pages=json.loads(response.read(100000))
    except urllib.error.HTTPError as exc:
        if exc.code==404:
            print("Old Pages origin is already disabled");return
        raise RuntimeError("Cannot read Pages settings: HTTP "+str(exc.code)) from None
    if pages.get("cname") not in (None,"cveharbor.com"):
        raise RuntimeError("Unexpected Pages custom domain; refusing to change it")
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers=headers,method="DELETE"),timeout=25) as response:
            if response.status!=204:raise RuntimeError("Unexpected Pages-disable response")
    except urllib.error.HTTPError as exc:
        raise RuntimeError("The website gate is active, but closing the old public Pages origin needs Pages-write permission: HTTP "+str(exc.code)) from None
    print("Old public GitHub Pages origin disabled after protected-site verification")


if __name__=="__main__":main()
