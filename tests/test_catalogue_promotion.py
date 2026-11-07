"""Exercise publication ordering and preservation using a temporary site and a fake provider."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import catalogue_promotion as release


class CataloguePromotionTests(unittest.TestCase):
    def rehearsal(self, drift=False):
        version = "44444444-4444-4444-8444-444444444444"
        uploads, activations = [], []
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            config = root / "source/site-gate/wrangler.json"
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({"assets": {}, "routes": []}))
            paths = release.CHANGED | release.LIVE_ONLY | {"data.js", "workspace/index.html"}
            for folder in ("before", "after"):
                for name in paths - release.LIVE_ONLY:
                    p = root / folder / name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(folder.encode() if name in release.CHANGED else b"historical")

            def origin(path, auth):
                if activations:
                    return (root / "after" / path).read_bytes()
                if path in release.CHANGED:
                    return b"unexpected" if drift else b"before"
                if path.endswith(".html"):
                    return b"historical"
                return b"current live bytes"

            def upload(command, check, env):
                self.assertEqual(command[1:3], ["versions", "upload"])
                self.assertNotIn("SITE_GATE_PASSWORD", env)
                self.assertNotIn("routes", json.loads(config.read_text()))
                for name in paths - release.CHANGED - {"workspace/index.html"}:
                    self.assertEqual((root / "after" / name).read_bytes(), b"current live bytes")
                self.assertEqual((root / "after/workspace/index.html").read_bytes(), b"historical")
                uploads.append(version)
                Path(env["WRANGLER_OUTPUT_FILE_PATH"]).write_text(json.dumps({
                    "type": "version-upload", "worker_name": "cveharbor-site", "version": 1, "version_id": version}))

            def provider(path, body=None):
                if path.startswith("/versions?"):
                    return {"items": [{"id": version if uploads else release.OLD_VERSION}]}
                self.assertEqual(path, "/deployments")
                if body:
                    self.assertEqual(body["versions"], [{"version_id": version, "percentage": 100}])
                    activations.append(version)
                return {"deployments": [{"id": "new" if activations else release.OLD_DEPLOYMENT,
                                         "versions": [{"version_id": version if activations else release.OLD_VERSION,
                                                       "percentage": 100}]}]}

            for check in ("approval", "policy", "evidence", "ready", "check_gate"):
                stack.enter_context(patch.object(release, check))
            stack.enter_context(patch.dict(os.environ, {"SITE_GATE_PASSWORD": "test-only-placeholder", "HOME": tmp,
                                "CLOUDFLARE_ACCOUNT_ID": "test", "CLOUDFLARE_API_TOKEN": "test",
                                "WRANGLER": "wrangler", "GITHUB_RUN_ID": "1"}))
            stack.enter_context(patch.object(release, "provider", side_effect=provider))
            stack.enter_context(patch.object(release, "protected_asset", side_effect=origin))
            stack.enter_context(patch.object(release.subprocess, "run", side_effect=upload))
            if drift:
                with self.assertRaisesRegex(RuntimeError, "baseline differs"):
                    release.publish(root)
            else:
                release.publish(root)
        return len(uploads), len(activations)

    def test_protects_live_feeds_and_activates_once(self):
        self.assertEqual(self.rehearsal(), (1, 1))

    def test_changed_baseline_stops_before_upload(self):
        self.assertEqual(self.rehearsal(drift=True), (0, 0))

    def test_only_exact_edge_tag_before_closing_body_is_removed(self):
        tag = b'<script src="https://analytics.example.test/immutable.js"></script>'
        page = b"<html><body>Catalogue</body></html>\n"
        observed = page.replace(b"</body>", tag + b"\n</body>")
        with patch.object(release, "BEACON_SHA256", release.digest(tag)):
            self.assertEqual(release.origin_bytes("admin-tools/index.html", observed), page)
            self.assertEqual(release.origin_bytes("data.js", observed), observed)
            self.assertEqual(release.origin_bytes("index.html", page), page)
            for other in (observed.replace(b"immutable", b"other"), page.replace(b"Catalogue", tag + b"Catalogue"),
                          observed.replace(b"Catalogue", b"Other"), observed.replace(tag, tag + tag)):
                self.assertNotEqual(release.origin_bytes("index.html", other), page)

    def test_only_the_owner_can_approve_the_current_catalogue_run(self):
        for identity, environment, state, allowed in (
            (release.OWNER_ID, release.SITE_ENV, "approved", True),
            (1, release.SITE_ENV, "approved", False),
            (release.OWNER_ID, "cloudflare-site-production", "approved", False),
            (release.OWNER_ID, release.SITE_ENV, "rejected", False),
        ):
            review = {"state": state, "user": {"id": identity}, "environments": [{"name": environment}]}
            with self.subTest(review=review), patch.dict(os.environ, {"GITHUB_RUN_ID": "123"}), \
                    patch.object(release, "github", return_value=[review]) as api:
                if allowed:
                    release.approval()
                else:
                    with self.assertRaises(RuntimeError):
                        release.approval()
                api.assert_called_once_with("/actions/runs/123/approvals")

    def test_owner_environment_rejects_bypass_and_other_reviewers(self):
        owner = {"type": "User", "reviewer": {"id": release.OWNER_ID}}
        extra = {"type": "User", "reviewer": {"id": 2}}
        for bypass, reviewers in ((True, [owner]), (False, []), (False, [extra]), (False, [owner, extra])):
            env = {"can_admins_bypass": bypass, "protection_rules": [
                {"type": "required_reviewers", "prevent_self_review": False, "reviewers": reviewers}]}
            with self.subTest(env=env), patch.object(release, "github", return_value=env), self.assertRaises(RuntimeError):
                release.policy()
