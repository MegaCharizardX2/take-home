"""Outpost VM Run Command runner, guest CVE script and ARM evidence readback.

Every external tool is a local fake on PATH: no Azure, VM or network is contacted.
Fakes never echo secret-shaped literals; synthetic values are built at runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNNER = HERE / "vm-run-command.sh"
GUEST = ROOT / "infra/mongo/cve-mitigations.sh"
BACKUP = ROOT / "infra/mongo/backup-now.sh"
EVIDENCE = HERE / "outpost-evidence.sh"
SUB = "00000000-0000-0000-0000-000000000001"
GUEST_NOISE = "guest-private-output-" + "x" * 8

# GNU-style sha256sum (macOS lacks --status); the runner and the wrapper both use it.
FAKE_SHA = r'''#!/usr/bin/env python3
import hashlib, sys
args = sys.argv[1:]
if args[:2] == ["-c", "--status"]:
    for line in sys.stdin:
        digest, _, path = line.rstrip("\n").partition("  ")
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != digest:
            sys.exit(1)
    sys.exit(0)
for path in args:
    print(hashlib.sha256(open(path, "rb").read()).hexdigest() + "  " + path)
'''

FAKE_AZ = r'''#!/usr/bin/env python3
import json, os, shutil, stat, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ["FIXTURE"])
with open(root / "trace", "a") as f:
    print(json.dumps(args), file=f)
case = os.environ.get("CASE", "")
if args[:2] == ["vm", "show"]:
    print("eastus2"); sys.exit(0)
if args[:2] == ["vm", "get-instance-view"]:
    print("PowerState/deallocated" if case == "stopped" else "PowerState/running"); sys.exit(0)
if args[:2] == ["vm", "restart"]:
    (root / "restarted").write_text("yes"); sys.exit(0)
if args[0] == "rest":
    method = args[args.index("--method") + 1]
    if method == "put":
        body = args[args.index("--body") + 1].removeprefix("@")
        mode = stat.S_IMODE(os.stat(body).st_mode)
        (root / "body-mode").write_text(oct(mode))
        shutil.copy(body, root / "body.json")
        sys.exit(1 if case == "rejected" else 0)
    if method == "delete":
        (root / "deleted").write_text("yes"); sys.exit(0)
    if method == "get":
        code = int(os.environ.get("EXIT", "0"))
        state = "Succeeded" if code == 0 else "Failed"
        # The runner must never read or print the guest's own output.
        print(json.dumps({"state": state, "code": code, "output": os.environ["NOISE"]})); sys.exit(0)
sys.exit(3)
'''


def tool(directory, name, body):
    path = Path(directory) / name
    path.write_text(body)
    path.chmod(0o755)
    return path


class RunnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        tool(self.bin, "az", FAKE_AZ)
        tool(self.bin, "sha256sum", FAKE_SHA)
        tool(self.bin, "sleep", "#!/bin/sh\nexit 0\n")

    def run_runner(self, mode, case="", code=0):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FIXTURE=str(self.root), CASE=case,
                   EXIT=str(code), NOISE=GUEST_NOISE, ARM_SUBSCRIPTION_ID=SUB, RUNNER_TEMP=str(self.root),
                   GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1")
        return subprocess.run(["bash", RUNNER, mode], env=env, capture_output=True, text=True)

    def calls(self):
        trace = self.root / "trace"
        return [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []

    def test_success_prints_only_state_code_and_label(self):
        reply = self.run_runner("cve-apply")
        self.assertEqual(reply.returncode, 0, reply.stderr)
        lines = reply.stdout.splitlines()
        self.assertEqual(lines[0], "VM Run Command cve-apply: state=Succeeded exitCode=0 (ok)")
        self.assertNotIn(GUEST_NOISE, reply.stdout + reply.stderr)
        self.assertEqual((self.root / "body-mode").read_text(), "0o600")
        self.assertTrue((self.root / "deleted").exists())
        self.assertFalse(list(self.root.glob("outpost-vm.*")), "private directory left behind")
        # The guest script travels only inside the request body, never on argv.
        for args in self.calls():
            self.assertFalse(any("OUTPOST_PAYLOAD" in a or "base64" in a for a in args))
        urls = [a[a.index("--url") + 1] for a in self.calls() if a[0] == "rest"]
        self.assertTrue(all("/virtualMachines/vm-mongo/runCommands/outpost-cve-apply-42-1?" in u for u in urls), urls)

    def test_failure_maps_to_fixed_label_and_still_deletes(self):
        for code, label in ((23, "algif_aead is loaded and in use"), (37, "running process still allows zlib"),
                            (90, "checksum mismatch"), (77, "unlabelled exit code")):
            with self.subTest(code=code):
                (self.root / "deleted").unlink(missing_ok=True)
                reply = self.run_runner("cve-verify", code=code)
                self.assertEqual(reply.returncode, 1)
                self.assertIn(f"state=Failed exitCode={code} (", reply.stdout)
                self.assertIn(label, reply.stdout)
                self.assertNotIn(GUEST_NOISE, reply.stdout + reply.stderr)
                self.assertTrue((self.root / "deleted").exists())

    def test_rejected_request_and_stopped_vm(self):
        reply = self.run_runner("backup", case="rejected")
        self.assertEqual(reply.returncode, 1)
        self.assertTrue((self.root / "deleted").exists())
        (self.root / "deleted").unlink()
        (self.root / "trace").unlink()
        reply = self.run_runner("cve-apply", case="stopped")
        self.assertEqual(reply.returncode, 1)
        self.assertIn("not running", reply.stderr)
        self.assertFalse((self.root / "deleted").exists())
        self.assertFalse(any(a[0] == "rest" for a in self.calls()))

    def test_invalid_mode_makes_no_call(self):
        for mode in ("", "apply", "cve-apply; true"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_runner(mode).returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_reboot_verify_restarts_before_the_verify_command(self):
        reply = self.run_runner("cve-reboot-verify")
        self.assertEqual(reply.returncode, 0, reply.stderr)
        verbs = [a[0:2] if a[0] == "vm" else ["rest", a[a.index("--method") + 1]] for a in self.calls()]
        self.assertLess(verbs.index(["vm", "restart"]), verbs.index(["rest", "put"]))
        self.assertIn(' verify\n', json.loads((self.root / "body.json").read_text())["properties"]["source"]["script"])

    def test_wrapper_runs_the_exact_reviewed_payload(self):
        for mode, guest, arg in (("cve-apply", GUEST, "apply"), ("backup", BACKUP, "run")):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_runner(mode).returncode, 0)
                script = json.loads((self.root / "body.json").read_text())["properties"]["source"]["script"]
                self.assertTrue(script.startswith("#!/bin/sh\n"))
                work = self.root / ("wrapper-" + arg)
                work.mkdir()
                fake = work / "bin"
                fake.mkdir()
                # A recording bash: proves decode, hash check, argument and status propagation.
                tool(fake, "bash", '#!/bin/sh\ncp "$1" "$OUT/payload"\necho "$2" > "$OUT/arg"\nexit 7\n')
                shutil.copy(self.bin / "sha256sum", fake / "sha256sum")
                env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", OUT=str(work), TMPDIR=str(work))
                reply = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
                self.assertEqual(reply.returncode, 7, reply.stderr)
                self.assertEqual((work / "payload").read_bytes(), guest.read_bytes())
                self.assertEqual((work / "arg").read_text().strip(), arg)
                self.assertEqual(sorted(p.name for p in work.iterdir()), ["arg", "bin", "payload"])
                tampered = re.sub(r"printf \"%s  %s\\n\" ([0-9a-f]{64})", lambda m: m.group(0).replace(m.group(1), "0" * 64), script)
                self.assertNotEqual(tampered, script)
                reply = subprocess.run(["sh", "-c", tampered], env=env, capture_output=True, text=True)
                self.assertEqual(reply.returncode, 90)

    def test_every_guest_exit_code_has_a_label(self):
        labels = set(map(int, re.findall(r"^\s+([0-9]+)\) echo '", RUNNER.read_text(), re.MULTILINE)))
        codes = {90}
        for script in (GUEST, BACKUP):
            codes |= set(map(int, re.findall(r"exit ([0-9]+)", script.read_text())))
        self.assertEqual(codes - labels, set())
        self.assertEqual(labels - codes - {0}, set(), "stale labels")


GUEST_FAKES = {
    "id": '#!/bin/sh\n[ -f "$FIX/notroot" ] && echo 1000 || echo 0\n',
    "uname": '#!/bin/sh\necho 5.15.0-1089-azure\n',
    "logger": '#!/bin/sh\nexit 0\n',
    "flock": '#!/bin/sh\nexit 0\n',
    "sleep": '#!/bin/sh\nexit 0\n',
    "mongod": '#!/bin/sh\ncat "$FIX/mongod-version"\n',
    "mongosh": '#!/bin/sh\n[ -f "$FIX/active" ]\n',
    "systemctl": r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
fix = Path(os.environ["FIX"]); a = sys.argv[1:]
with open(fix / "systemctl.log", "a") as f: print(" ".join(a), file=f)
if a[:2] == ["show", "-p"]: print((fix / "pid").read_text().strip())
elif a[0] == "is-active": sys.exit(0 if (fix / "active").exists() else 3)
elif a[0] == "daemon-reload": pass
elif a[0] == "restart":
    pid = int((fix / "pid").read_text()) + 1
    (fix / "pid").write_text(str(pid))
    d = fix / "root/proc" / str(pid); d.mkdir(parents=True)
    dropin = fix / "root/etc/systemd/system/mongod.service.d/10-outpost-cve-2025-14847.conf"
    line = [l for l in dropin.read_text().splitlines() if l.startswith("ExecStart=/")][-1]
    (d / "cmdline").write_bytes(b"\0".join(w.encode() for w in line.removeprefix("ExecStart=").split()) + b"\0")
    (fix / "active").write_text("yes")
elif a[0] == "start": sys.exit(0 if (fix / "backup-ok").exists() else 1)
else: sys.exit(5)
''',
    "modprobe": r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
fix = Path(os.environ["FIX"]); modules = fix / "root/proc/modules"; a = sys.argv[1:]
rule = fix / "root/etc/modprobe.d/outpost-cve-2026-31431.conf"
lines = [l for l in modules.read_text().splitlines() if l]
if a == ["-r", "algif_aead"]:
    if (fix / "in-use").exists(): sys.exit(1)
    modules.write_text("".join(l + "\n" for l in lines if not l.startswith("algif_aead ")))
elif a == ["algif_aead"]:
    if rule.exists() and "install algif_aead /bin/false" in rule.read_text() and not (fix / "rule-ignored").exists():
        sys.exit(1)
    modules.write_text("".join(l + "\n" for l in lines + ["algif_aead 20480 0 - Live 0x0"]))
else: sys.exit(2)
''',
}


class GuestTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.fix = Path(temp.name)
        root = self.fix / "root"
        for d in ("etc/modprobe.d", "etc/systemd/system", "proc/100", "run/lock", "lib/modules/5.15.0-1089-azure"):
            (root / d).mkdir(parents=True)
        (root / "etc/os-release").write_text('NAME="Ubuntu"\nVERSION_ID="20.04"\n')
        (root / "etc/mongod.conf").write_text("net:\n  bindIp: 127.0.0.1\n  port: 27017\n")
        (root / "lib/modules/5.15.0-1089-azure/modules.builtin").write_text("kernel/crypto/sha256_generic.ko\n")
        # Phase-1 state: algif_aead loaded, mongod running with the default compressors.
        (root / "proc/modules").write_text("af_alg 32768 1 algif_aead, Live 0x0\nalgif_aead 20480 0 - Live 0x0\n")
        (root / "proc/100/cmdline").write_bytes(b"/usr/local/bin/mongod\0--config\0/etc/mongod.conf\0")
        (self.fix / "pid").write_text("100")
        (self.fix / "active").write_text("yes")
        (self.fix / "mongod-version").write_text("db version v6.0.26\nBuild Info: {}\n")
        self.bin = self.fix / "bin"
        self.bin.mkdir()
        for name, body in GUEST_FAKES.items():
            tool(self.bin, name, body)

    def guest(self, mode, script=GUEST):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FIX=str(self.fix), OUTPOST_SYSROOT=str(self.fix / "root"))
        reply = subprocess.run(["bash", script, mode], env=env, capture_output=True, text=True)
        self.assertEqual(reply.stdout + reply.stderr, "", "the guest must print nothing")
        return reply.returncode

    def restarts(self):
        log = self.fix / "systemctl.log"
        return log.read_text().count("restart mongod.service") if log.exists() else 0

    def test_apply_then_verify_is_idempotent(self):
        self.assertEqual(self.guest("verify"), 24)  # baseline: no block rule yet
        self.assertEqual(self.guest("apply"), 0)
        root = self.fix / "root"
        self.assertNotIn("algif_aead ", (root / "proc/modules").read_text())
        rule = (root / "etc/modprobe.d/outpost-cve-2026-31431.conf").read_text()
        self.assertIn("install algif_aead /bin/false\n", rule)
        self.assertEqual(stat.S_IMODE((root / "etc/modprobe.d/outpost-cve-2026-31431.conf").stat().st_mode), 0o644)
        args = (root / "proc/101/cmdline").read_bytes().split(b"\0")
        self.assertEqual(args[args.index(b"--networkMessageCompressors") + 1], b"snappy,zstd")
        self.assertEqual(self.restarts(), 1)
        self.assertEqual(self.guest("apply"), 0)
        self.assertEqual(self.guest("verify"), 0)
        self.assertEqual(self.restarts(), 1, "a second apply must not restart mongod")

    def test_failures_have_distinct_codes(self):
        self.assertEqual(self.guest("apply"), 0)
        root = self.fix / "root"
        cases = {
            11: lambda: (root / "etc/os-release").write_text('VERSION_ID="22.04"\n'),
            12: lambda: (self.fix / "mongod-version").write_text("db version v7.0.1\n"),
            21: lambda: (root / "lib/modules/5.15.0-1089-azure/modules.builtin").write_text("kernel/crypto/algif_aead.ko\n"),
            24: lambda: (root / "etc/modprobe.d/outpost-cve-2026-31431.conf").write_text("blacklist algif_aead\n"),
            25: lambda: (root / "proc/modules").write_text("algif_aead 20480 0 - Live 0x0\n"),
            26: lambda: (self.fix / "rule-ignored").write_text("yes"),
            34: lambda: (root / "etc/systemd/system/mongod.service.d/10-outpost-cve-2025-14847.conf").write_text("[Service]\n"),
            35: lambda: (root / "etc/mongod.conf").write_text("net:\n  compression:\n    compressors: zlib\n"),
            36: lambda: (self.fix / "active").unlink(),
            37: lambda: (root / "proc/101/cmdline").write_bytes(b"/usr/local/bin/mongod\0--config\0/etc/mongod.conf\0"),
            10: lambda: (self.fix / "notroot").write_text("yes"),
        }
        for code, breaker in cases.items():
            with self.subTest(code=code):
                snapshot = self.fix.parent / (self.fix.name + "-snapshot")
                shutil.copytree(self.fix, snapshot, symlinks=True)
                try:
                    breaker()
                    self.assertEqual(self.guest("verify"), code)
                finally:
                    shutil.rmtree(self.fix)
                    shutil.move(snapshot, self.fix)
        self.assertEqual(self.guest("nonsense"), 10)

    def test_module_in_use_asks_for_a_reboot(self):
        (self.fix / "in-use").write_text("yes")
        self.assertEqual(self.guest("apply"), 23)

    def test_backup_now(self):
        self.assertEqual(self.guest("run", BACKUP), 40)
        (self.fix / "backup-ok").write_text("yes")
        self.assertEqual(self.guest("run", BACKUP), 0)
        self.assertEqual(self.guest("other", BACKUP), 10)


FAKE_EVIDENCE_AZ = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
url = a[a.index("--url") + 1]
fixtures = json.loads(open(os.environ["RESPONSES"]).read())
for key in sorted(fixtures, key=len, reverse=True):
    if key in url:
        print(json.dumps(fixtures[key])); sys.exit(0)
sys.exit(1)
'''


def evidence_fixtures():
    rg = f"/subscriptions/{SUB}/resourceGroups/takehome-rg"
    account = rg + "/providers/Microsoft.Storage/storageAccounts/stoutpost123456789a"
    principal = "11111111-2222-3333-4444-" + "5" * 12
    writer = "99999999-8888-7777-6666-" + "5" * 12
    return principal, {
        "/storageAccounts?api-version": {"value": [{"name": "stoutpost123456789a"}, {"name": "sttakehometf20581"}]},
        "/storageAccounts/stoutpost123456789a?api-version": {"properties": {
            "publicNetworkAccess": "Disabled", "allowBlobPublicAccess": False, "allowSharedKeyAccess": False,
            "networkAcls": {"defaultAction": "Deny"},
            "encryption": {"keySource": "Microsoft.Keyvault", "keyvaultproperties": {"keyname": "backup-cmk"},
                           "identity": {"userAssignedIdentity": rg + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-backup-cmk"}}}},
        "/containers/backups?": {"properties": {"publicAccess": "None"}},
        "/privateEndpointConnections?": {"value": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]},
        "/policyExemptions?": {"value": []},
        "/networkInterfaces/nic-mongo?": {"properties": {"ipConfigurations": [{"properties": {"privateIPAddress": "10.84.2.36"}}]}},
        "/publicIPAddresses?": {"value": [{"name": "pip-ingress"}, {"name": "pip-nat"}]},
        "/networkSecurityGroups/nsg-mongo?": {"properties": {"securityRules": [
            {"properties": {"direction": "Inbound", "access": "Allow", "destinationPortRange": "27017"}},
            {"properties": {"direction": "Inbound", "access": "Deny", "destinationPortRange": "27017"}},
            {"properties": {"direction": "Inbound", "access": "Deny", "destinationPortRange": "22"}}]}},
        "/userAssignedIdentities/id-mongo?": {"properties": {"principalId": principal}},
        "/roleDefinitions?": {"value": [{"name": writer, "properties": {"roleName": "Lab Backup Writer"}}]},
        "/roleAssignments?": {"value": [{"properties": {
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{writer}",
            "scope": account + "/blobServices/default/containers/backups"}}]},
        "/managedClusters/aks-outpost?": {"properties": {"apiServerAccessProfile": {
            "enableVnetIntegration": True, "enablePrivateCluster": False, "authorizedIPRanges": ["1.2.3.4/32"]}}},
    }


class EvidenceTests(unittest.TestCase):
    def evidence(self, responses, http="403"):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            tool(d, "az", FAKE_EVIDENCE_AZ)
            tool(d, "curl", f"#!/bin/sh\nprintf '%s' '{http}'\n")
            (d / "responses.json").write_text(json.dumps(responses))
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", RESPONSES=str(d / "responses.json"),
                       ARM_SUBSCRIPTION_ID=SUB, RUNNER_TEMP=directory)
            reply = subprocess.run(["bash", EVIDENCE], env=env, capture_output=True, text=True)
            self.assertFalse(list(d.glob("outpost-evidence.*")))
            return reply

    def test_remediated_state_passes_without_printing_values(self):
        principal, responses = evidence_fixtures()
        reply = self.evidence(responses)
        self.assertEqual(reply.returncode, 0, reply.stderr)
        self.assertEqual(sum(line.startswith("PASS ") for line in reply.stdout.splitlines()), 8)
        self.assertIn("(HTTP 403)", reply.stdout)
        for private in (principal, "1.2.3.4", "10.84.2.36", "stoutpost123456789a"):
            self.assertNotIn(private, reply.stdout + reply.stderr)

    def test_each_weakness_fails_its_own_check(self):
        def change(path, value):
            def apply(r):
                node = r
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return apply
        acct = "/storageAccounts/stoutpost123456789a?api-version"
        cases = [
            (11, change([acct, "properties", "publicNetworkAccess"], "Enabled")),
            (11, change([acct, "properties", "encryption", "keySource"], "Microsoft.Storage")),
            (12, change(["/containers/backups?", "properties", "publicAccess"], "Container")),
            (13, change(["/policyExemptions?", "value"], [{"name": "wiz-public-backup-baseline"}])),
            (15, change(["/networkInterfaces/nic-mongo?", "properties", "ipConfigurations", 0, "properties", "publicIPAddress"], {"id": "x"})),
            (15, change(["/publicIPAddresses?", "value"], [{"name": "pip-mongo"}])),
            (16, change(["/networkSecurityGroups/nsg-mongo?", "properties", "securityRules", 2, "properties", "access"], "Allow")),
            (17, change(["/roleAssignments?", "value"], [{"properties": {"roleDefinitionId": "/x/virtual-machine-contributor", "scope": "/x"}}])),
            (18, change(["/managedClusters/aks-outpost?", "properties", "apiServerAccessProfile", "authorizedIPRanges"], [])),
            (18, change(["/managedClusters/aks-outpost?", "properties", "apiServerAccessProfile", "authorizedIPRanges"], ["0.0.0.0/32"])),
        ]
        for code, mutate in cases:
            _, responses = evidence_fixtures()
            mutate(responses)
            with self.subTest(code=code):
                reply = self.evidence(responses)
                self.assertEqual(reply.returncode, code, reply.stdout + reply.stderr)
                self.assertTrue(reply.stderr.startswith("FAIL "))
        _, responses = evidence_fixtures()
        self.assertEqual(self.evidence(responses, http="200").returncode, 14)


if __name__ == "__main__":
    unittest.main()
