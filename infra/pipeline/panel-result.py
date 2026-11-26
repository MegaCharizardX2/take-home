"""Print only the lab script's fixed results; reject incomplete or failed invokes."""
import json
from pathlib import Path
import sys

expected = ["PASS binding annotation", "PASS ordinary pod admitted", "PASS privileged pod denied by deny-privileged"]
failures = {"FAIL preflight", "FAIL binding guard", "FAIL binding annotation", "FAIL deployed image",
            "FAIL policy attribution", "FAIL ordinary pod", "FAIL privileged pod admitted", "FAIL wrong denial"}
try:
    reply = json.loads(Path(sys.argv[1]).read_text())
    results = [line for line in reply["logs"].splitlines() if line in expected or line in failures]
    for result in results:
        print(result)
    ok = (reply["provisioningState"] == "Succeeded" and type(reply["exitCode"]) is int
          and reply["exitCode"] == 0 and isinstance(reply["id"], str) and bool(reply["id"].strip())
          and results == expected)
except (OSError, ValueError, KeyError, IndexError, AttributeError, TypeError):
    ok = False
if not ok:
    sys.exit("FAIL incomplete or unsuccessful AKS evidence")
