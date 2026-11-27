"""Render scanner inputs from the one UTC lab expiry and the reviewed exceptions."""
from datetime import date, datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def render(name, root=ROOT, today=None):
    expiry = date.fromisoformat((root / "infra/lab-expiry.txt").read_text().strip())
    current = (today or datetime.now(timezone.utc).date()) < expiry
    if name == "checkov.yaml":
        return (root / "policy/.checkov.yaml").read_text() if current else "skip-check: []\n"
    if name == "trivy.yaml":
        if not current:
            return "misconfigurations: []\n"
        return (root / "policy/.trivyignore.yaml").read_text().replace("LAB_EXPIRY", expiry.isoformat())
    if name == "public-access.tf":
        source = (root / "infra/public-access.tf").read_text()
        declaration = 'resource "azurerm_network_security_rule" "ingress" {'
        if source.count(declaration) != 1:
            raise ValueError("Expected a single ingress resource")
        annotation = f"#trivy:ignore:AZU-0047:exp:{expiry}\n" if current else ""
        return source.replace(declaration, annotation + declaration)
    raise ValueError("Unknown scanner input")


if __name__ == "__main__":
    sys.stdout.write(render(sys.argv[1]))
