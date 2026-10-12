#!/usr/bin/env python3
"""Static checks on the shipped proxyto service definitions.

The systemd unit reads its instance name from an EnvironmentFile. systemd
expands ``${VAR}`` but has no shell, so a shell-style ``${VAR:-default}``
is passed through literally and the daemon rejects it as an invalid instance
name. That defect is invisible until the unit is restarted, and on a host
where the unit had never been restarted since it shipped, it took the service
down rather than failing loudly at build time.

These checks are deliberately static: they run without systemd, without root,
and without a built daemon.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

UNIT = os.path.join(ROOT, "proxyto.service")
INITD = os.path.join(ROOT, "etc", "init.d", "proxyto")
CONFD = os.path.join(ROOT, "etc", "conf.d", "proxyto")

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


if not os.path.exists(UNIT):
    print(f"FAIL: missing {UNIT}")
    sys.exit(1)

unit = read(UNIT)

# Comments legitimately discuss the forbidden syntax; only directives matter.
directives = [
    line for line in unit.splitlines() if line.strip() and not line.strip().startswith("#")
]

# 1. No shell default expansion anywhere in the unit. systemd does not run a
#    shell, so the whole `:-` form survives verbatim into argv.
check(
    not [l for l in directives if ":-" in l],
    "systemd unit contains shell ':-' default expansion, which systemd "
    "passes through literally: " + repr([l for l in directives if ":-" in l]),
)

# 2. Every ${VAR} in ExecStart must be satisfiable from the EnvironmentFile.
exec_start = ""
for line in unit.splitlines():
    if line.strip().startswith("ExecStart="):
        exec_start = line.strip()
        break

check(bool(exec_start), "systemd unit has no ExecStart line")

referenced = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", exec_start))
if referenced and os.path.exists(CONFD):
    confd = read(CONFD)
    defined = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=", confd, re.M))
    missing = referenced - defined
    check(
        not missing,
        f"ExecStart references variable(s) not defined in "
        f"/etc/conf.d/proxyto: {sorted(missing)}",
    )

# 3. The EnvironmentFile must be optional-but-present: '-' tolerates absence,
#    which would then leave the instance name empty and fail the same way.
if referenced:
    check(
        "EnvironmentFile" in unit,
        "ExecStart uses variables but the unit sets no EnvironmentFile",
    )

# 4. The OpenRC init script and the systemd unit must agree on how the
#    instance name is supplied, so an operator is not misled about which
#    mechanism actually applies on a given host.
if os.path.exists(INITD):
    initd = read(INITD)
    check(
        "proxyto_name" in initd,
        "OpenRC init script no longer honours proxyto_name from /etc/conf.d/proxyto",
    )

if failures:
    print("FAIL: service definition checks failed")
    for line in failures:
        print("  - " + line)
    sys.exit(1)

print("ok - service definition checks passed")
