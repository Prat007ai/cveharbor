"""Install origin-scoped Basic authentication for private-site release probes."""
import os
import urllib.request


def install_site_auth():
    password=os.environ.get("SITE_GATE_PASSWORD")
    if not password:return
    username=os.environ.get("SITE_GATE_USERNAME","cveharbor")
    manager=urllib.request.HTTPPasswordMgrWithDefaultRealm()
    for origin in ("https://cveharbor.com/","https://www.cveharbor.com/"):
        manager.add_password("CVEHarbor development",origin,username,password)
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(manager)))
