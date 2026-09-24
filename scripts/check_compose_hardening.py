#!/usr/bin/env python3
"""The compose hardening gate.

The container job scans the Dockerfile and the Kubernetes manifests
with Trivy's configuration scanner, and kube-linter reads the
manifests again for posture. None of them reads docker-compose.yml:
Trivy's configuration rules cover Dockerfiles, Kubernetes, Terraform,
and the cloud template formats, and a compose file passes through them
reporting nothing at all. That silence is the reason this file exists,
because the compose file is the one a reader runs first, and its
header claims least privilege at the container boundary (D-042).

So the claim is checked here instead of assumed: every service that
runs a container drops all capabilities, refuses privilege escalation,
and mounts its root filesystem read-only, and nothing in the file asks
for the host's namespaces or a privileged container. A property that
is only a comment is a property that leaves on the first refactor.

Run from the repository root; exits nonzero naming the service and the
line that is missing.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yml"

# Each required property, with the failure it prevents.
REQUIRED = (
    ("cap_drop", "every Linux capability is dropped"),
    ("security_opt", "privilege escalation is refused"),
    ("read_only", "the root filesystem is read-only"),
)

# Keys that hand a container the host, none of which this stack needs.
FORBIDDEN = (
    "privileged",
    "network_mode",
    "pid",
    "ipc",
    "userns_mode",
    "devices",
    "cap_add_all",
)


def check_service(name: str, service: dict[str, object]) -> list[str]:
    problems: list[str] = []
    for key, why in REQUIRED:
        if key not in service:
            problems.append(f"{name}: no {key}, so {why} is not stated")
    cap_drop = service.get("cap_drop")
    if isinstance(cap_drop, list) and "ALL" not in [str(c).upper() for c in cap_drop]:
        problems.append(f"{name}: cap_drop does not drop ALL")
    options = service.get("security_opt")
    if isinstance(options, list) and not any(
        str(o).replace(" ", "") == "no-new-privileges:true" for o in options
    ):
        problems.append(f"{name}: security_opt lacks no-new-privileges:true")
    if service.get("read_only") is not True:
        problems.append(f"{name}: read_only is not true")
    for key in FORBIDDEN:
        if key in service:
            problems.append(f"{name}: {key} hands the container the host")
    # A bind mount from the host is not forbidden outright, but a
    # writable one into a read-only container is a contradiction worth
    # failing on.
    for volume in service.get("volumes", []) or []:  # type: ignore[union-attr]
        text = str(volume)
        if text.startswith(("/", ".", "~")) and not text.endswith(":ro"):
            problems.append(f"{name}: writable host mount {text}")
    return problems


def main() -> int:
    document = yaml.safe_load(COMPOSE.read_text())
    services = document.get("services", {})
    if not services:
        print("compose hardening: no services found", file=sys.stderr)
        return 2
    problems: list[str] = []
    for name, service in services.items():
        problems.extend(check_service(name, service))
    for problem in problems:
        print(f"compose hardening: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"compose hardening: {len(services)} services hold every property")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
