#!/usr/bin/env python3
"""Enumerate the attack surface reachable from the `shell` domain.

Inputs (pulled read-only from the device into runs/android/):
  *_service_contexts   -> binder service name -> SELinux type
  *_sepolicy.cil       -> allow rules (text form of the policy)

Output: which non-AOSP binder services the adb shell uid can find + call.
"""
import os
import re
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))

SVC_FILES = [
    "plat_service_contexts",
    "system_ext_service_contexts",
    "vendor_service_contexts",
    "odm_service_contexts",
    "vndservice_contexts",
]
CIL_FILES = [
    "plat_sepolicy.cil",
    "plat_pub_versioned.cil",
    "system_ext_sepolicy.cil",
    "vendor_sepolicy.cil",
    "odm_sepolicy.cil",
]

ALLOW_RE = re.compile(r"\(allow\s+(\S+)\s+(\S+)\s+\((\w+)(?:\s*\(([^)]*)\))?\s*\)\s*\)")
ATTR_RE = re.compile(r"\(typeattributeset\s+(\S+)\s+\(([^)]*)\)\s*\)")


def read(name):
    path = os.path.join(BASE, name)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_service_types():
    """service name -> set(types)"""
    mapping = defaultdict(set)
    for fn in SVC_FILES:
        text = read(fn)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name, ctx = parts[0], parts[1]
            m = re.search(r"u:object_r:([^:]+):s0", ctx)
            if m:
                mapping[name].add(m.group(1))
    return mapping


def load_rules():
    attr_members = defaultdict(set)
    allows = []
    for fn in CIL_FILES:
        text = read(fn)
        if not text:
            continue
        for m in ATTR_RE.finditer(text):
            attr, members = m.group(1), m.group(2).split()
            attr_members[attr].update(members)
        for m in ALLOW_RE.finditer(text):
            src, tgt, cls, perms = m.group(1), m.group(2), m.group(3), m.group(4)
            plist = perms.split() if perms else ["*"]
            allows.append((src, tgt, cls, plist))
    return attr_members, allows


def expand(name, attr_members, _seen=None):
    """Return the concrete set of types denoted by `name` (attribute expansion)."""
    if _seen is None:
        _seen = set()
    if name in _seen:
        return set()
    _seen.add(name)
    if name not in attr_members:
        return {name}
    out = {name}
    for member in attr_members[name]:
        out |= expand(member, attr_members, _seen)
    return out


def main():
    svc = load_service_types()
    attr_members, allows = load_rules()

    # type -> service names published with that label
    type_to_svc = defaultdict(set)
    for name, types in svc.items():
        for t in types:
            type_to_svc[t].add(name)

    findable = defaultdict(set)   # type -> perms allowed to shell on service_manager
    callable_ = defaultdict(set)  # type -> perms allowed to shell on binder

    for src, tgt, cls, perms in allows:
        if "shell" not in expand(src, attr_members):
            continue
        if cls == "service_manager" and "find" in perms or (cls == "service_manager" and "*" in perms):
            findable[tgt] |= set(perms)
        elif cls == "binder" and ("call" in perms or "*" in perms):
            callable_[tgt] |= set(perms)

    print("=" * 78)
    print("SELinux surface reachable from u:r:shell:s0")
    print("=" * 78)
    print(f"service_contexts entries : {len(svc)}")
    print(f"allow rules parsed       : {len(allows)}")
    print(f"label types findable     : {len(findable)}")
    print(f"label types callable     : {len(callable_)}")

    # Services the shell can both find and call
    full = []
    for t, names in type_to_svc.items():
        if t in findable and t in callable_:
            for n in names:
                full.append((n, t))

    print(f"\n--- shell CAN find+call ({len(full)}) ---")
    for n, t in sorted(full):
        print(f"  {n:55s} {t}")

    print(f"\n--- shell can find but NOT call ({sum(1 for t in type_to_svc if t in findable and t not in callable_)}) ---")
    for t, names in sorted(type_to_svc.items()):
        if t in findable and t not in callable_:
            print(f"  {sorted(names)[0]:55s} {t}")

    # Non-AOSP looking services in the callable set
    interesting = []
    for n, t in sorted(full):
        low = n.lower()
        if any(k in low for k in ("mi", "xiaomi", "xring", "mtk", "mediatek", "security",
                                  "secret", "soter", "sentinel", "mqsas", "misight",
                                  "factory", "atc", "diagnos", "dfx", "patch", "auth",
                                  "keymint", "tee", "trust", "power", "perf", "gaming")):
            interesting.append((n, t))
    print(f"\n--- VENDOR/OEM-looking services in the shell-callable set ({len(interesting)}) ---")
    for n, t in interesting:
        print(f"  {n:55s} {t}")

    # Which labels are reachable at all, regardless of service registration
    print("\n--- labels where shell has binder call but no registered name ---")
    unreg = sorted(t for t in callable_ if t not in type_to_svc)
    print(f"  {len(unreg)} labels")


if __name__ == "__main__":
    main()
