# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""A real-world example: govern a container deployment on a remote Docker host over SSH.

This is the shape most people will actually use Interlock for — an agent proposes a
deploy, a human countersigns it, and it rolls out stage by stage with live precondition
checks and post-verify. The two adapters below (execute over SSH; probe over SSH,
read-only) are the entire integration surface. Nothing about a specific host is baked in —
pass your own ``host`` (an ssh alias) and ``deploy_root``.

Actions this example understands (register them in the policy):
  write_file      params: {path: <rel under deploy_root>, content: <text>, mode?: '644'|'600'}
  pull_image      params: {ref: <image ref or name:tag>}
  compose_up      params: {dir: <project dir under deploy_root>}      (creating)
  container_stop  params: {name: <container>}
  container_start params: {name: <container>}                          (creating)

Probe checks:
  host_up            -> 'true' if ssh works
  file_present       probe: {path: <rel>}      -> 'true'|'false'
  container_running  probe: {name: <container>} -> 'true'|'false'
  port_free          probe: {port: <n>}         -> 'true'|'false' (tcp+udp listeners)
  mem_available_mb   probe: {}                   -> integer MB

Security: every remote command is assembled with ``shlex.quote`` and file content travels
base64-encoded, so plan values never interpolate into a remote shell unescaped. Paths and
names are validated to a safe charset. This adapter still runs as whatever your ssh key is
authorized for — scope that key (a forced command / restricted user) in production.
"""
from __future__ import annotations

import base64
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from interlock.adapters import ExecResult, ProbeResult          # noqa: E402
from interlock.approval import FileStore                        # noqa: E402
from interlock.audit import FileAuditSink                       # noqa: E402
from interlock.engine import Interlock                          # noqa: E402
from interlock.policy import Policy, registry                   # noqa: E402

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _rel_ok(rel: str) -> bool:
    return bool(rel) and _SAFE.match(rel) and ".." not in rel.split("/")


class SSHDockerExecutor:
    def __init__(self, host: str, deploy_root: str, *, timeout: int = 600):
        self.host, self.root, self.timeout = host, deploy_root.rstrip("/"), timeout

    def _ssh(self, remote_cmd: str) -> tuple[int, str, str]:
        p = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.host, remote_cmd],
            capture_output=True, text=True, timeout=self.timeout)  # noqa: S603
        return p.returncode, p.stdout, p.stderr

    def execute(self, action: str, params: dict, target: dict | None) -> ExecResult:
        try:
            cmd = self._build(action, params)
        except ValueError as e:
            return ExecResult(ok=False, detail=f"refused: {e}")
        if cmd is None:
            return ExecResult(ok=False, detail=f"unknown action {action!r}")
        rc, out, err = self._ssh(cmd)
        return ExecResult(ok=(rc == 0), detail=f"rc={rc} {(out or err).strip()[-400:]}".strip())

    def _build(self, action: str, params: dict) -> str | None:
        if action == "write_file":
            rel, content, mode = params.get("path"), params.get("content", ""), str(params.get("mode", "644"))
            if not _rel_ok(rel):
                raise ValueError(f"unsafe path {rel!r}")
            if mode not in ("644", "600"):
                raise ValueError("mode must be 644|600")
            tgt = f"{self.root}/{rel}"
            b64 = base64.b64encode(content.encode()).decode()
            return (f"mkdir -p {shlex.quote(str(Path(tgt).parent))} && "
                    f"printf %s {shlex.quote(b64)} | base64 -d > {shlex.quote(tgt)} && "
                    f"chmod {mode} {shlex.quote(tgt)}")
        if action == "pull_image":
            return f"docker pull {shlex.quote(params['ref'])}"
        if action == "compose_up":
            d = params.get("dir")
            if not _rel_ok(d) or "/" in d:
                raise ValueError(f"unsafe dir {d!r}")
            cf = f"{self.root}/{d}/compose.yaml"
            return f"docker compose -f {shlex.quote(cf)} up -d"
        if action in ("container_stop", "container_start"):
            name = params.get("name", "")
            if not _SAFE.match(name):
                raise ValueError(f"unsafe container name {name!r}")
            verb = "stop" if action == "container_stop" else "start"
            return f"docker {verb} {shlex.quote(name)}"
        return None


class SSHDockerProber:
    def __init__(self, host: str, deploy_root: str):
        self.host, self.root = host, deploy_root.rstrip("/")

    def _ssh(self, remote_cmd: str) -> tuple[int, str]:
        p = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.host, remote_cmd],
            capture_output=True, text=True, timeout=30)  # noqa: S603
        return p.returncode, p.stdout.strip()

    def probe(self, check: str, spec: dict) -> ProbeResult:
        try:
            if check == "host_up":
                rc, _ = self._ssh("true")
                return ProbeResult(rc == 0, "true" if rc == 0 else "false")
            if check == "container_running":
                name = spec["name"]
                rc, out = self._ssh(f"docker ps --filter name=^/{shlex.quote(name)}$ --filter status=running --format '{{{{.Names}}}}'")
                return ProbeResult(True, "true" if out == name else "false")
            if check == "port_free":
                port = str(spec["port"])
                rc, out = self._ssh("ss -Htuln")
                listening = any(line.split()[4].rsplit(":", 1)[-1] == port
                                for line in out.splitlines() if len(line.split()) >= 5 and ":" in line.split()[4])
                return ProbeResult(True, "false" if listening else "true")
            if check == "mem_available_mb":
                rc, out = self._ssh("awk '/^MemAvailable:/{print $2}' /proc/meminfo")
                return ProbeResult(out.isdigit(), int(out) // 1024 if out.isdigit() else None)
            if check == "file_present":
                rel = spec["path"]
                if not _rel_ok(rel):
                    return ProbeResult(False, detail="unsafe path")
                rc, out = self._ssh(f"test -e {shlex.quote(self.root + '/' + rel)} && echo true || echo false")
                return ProbeResult(True, out)
        except Exception as e:  # noqa: BLE001
            return ProbeResult(False, detail=f"probe error: {e}")
        return ProbeResult(False, detail=f"no probe for {check!r}")


def build_engine(host: str, deploy_root: str, store_dir: str, audit_path: str,
                 *, ttl_seconds: int = 72 * 3600) -> Interlock:
    policy = Policy(
        action_registry=registry(
            mutating=["write_file", "pull_image", "container_stop"],
            creating=["compose_up", "container_start"],
        ),
        unknown_action="reject",
    )
    return Interlock(
        policy=policy,
        store=FileStore(store_dir),
        audit=FileAuditSink(audit_path),
        executor=SSHDockerExecutor(host, deploy_root),
        prober=SSHDockerProber(host, deploy_root),
        ttl_seconds=ttl_seconds,
    )
