#!/usr/bin/env python3
"""Reproduce the FTPS/TLS 1.3 upload-truncation bug against a local SFTPGo instance.

Background
----------
Some libcurl versions close the FTPS data connection without reading the
TLS 1.3 post-handshake NewSessionTicket the server sends right after the
handshake. On Linux, close()-ing a socket that still has unread inbound
data makes the kernel send a TCP RST instead of a FIN, and a RST discards
any of the peer's own queued-but-unacknowledged bytes -- truncating the
upload. TLS 1.2 has no post-handshake message, so the same client code
works fine there. This was fixed in curl 8.9.0 (graceful data-connection
shutdown) and refined through 8.22.0 (TLS session reuse on the data
connection). See the analysis this script accompanies for the full
root-cause writeup and references.

What this script does
----------------------
1. Builds the sftpgo binary from this checkout (unless --sftpgo-bin is given).
2. Starts a throwaway local SFTPGo instance with explicit FTPS and a
   self-signed certificate, once per "profile":
     - "default"        : no max_tls_version cap (today's shipped default)
     - "capped-tls12"    : max_tls_version=12 (the mitigation added alongside
                            this script, see ftpd.Binding.MaxTLSVersion)
3. For every curl binary in --curl-dir (one per bundled version) and every
   repeat, uploads a freshly generated random file over explicit FTPS,
   rate-limited to make an in-flight tail at close() likely, and compares
   the file SFTPGo actually wrote against the source (size + SHA-256).
4. Prints a result matrix and a plain-English summary.

This is a best-effort, timing-sensitive reproduction: it runs over loopback,
so whether a RST actually drops bytes depends on kernel buffering and
scheduling at the moment curl closes the data connection. --limit-rate and
--repeat exist to make the race easier to hit; a single "no truncation
observed" run for a known-buggy curl version is not proof the bug is fixed,
only that it didn't trigger this time. In our own testing against SFTPGo
specifically, even curl 7.88.1 (pre-8.9.0) did not reproduce the truncation
-- see README.md ("What we actually observed") for why: SFTPGo's Go
crypto/tls sends exactly one session ticket per connection, and curl's
close sequence happens to drain exactly one incidental read, which is
enough to consume it. Servers that send two tickets by default (vsftpd,
ProFTPD) are the more likely place to see this trigger reliably. The
max_tls_version=12 mitigation this script also validates removes the
trigger entirely, independent of any of this.

Usage
-----
    python3 repro.py [--curl-dir bin] [--file-size-mb 24] [--limit-rate 2M]
                      [--repeat 3] [--keep] [--sftpgo-bin PATH]
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

DEFAULT_CURL_DIR = SCRIPT_DIR / "bin"
FTP_USER = "tlsrepro"
FTP_PASSWORD = "tlsrepro-Pwd1234!"


@dataclasses.dataclass
class Profile:
    name: str
    max_tls_version: int
    description: str


PROFILES = [
    Profile("default", 0, "no max_tls_version cap (today's shipped default: TLS 1.3 allowed)"),
    Profile("capped-tls12", 12, "max_tls_version=12 (this patch's mitigation: TLS 1.3 refused)"),
]


@dataclasses.dataclass
class AttemptResult:
    profile: str
    curl_version: str
    repeat: int
    curl_exit_code: int
    curl_error: str
    negotiated_tls: list[str]
    remote_exists: bool
    remote_size: int
    source_size: int
    size_match: bool
    sha_match: bool
    elapsed_s: float

    @property
    def outcome(self) -> str:
        if self.curl_exit_code != 0 and not self.remote_exists:
            return "CURL_ERROR"
        if not self.remote_exists:
            return "MISSING"
        if not self.size_match or not self.sha_match:
            return "TRUNCATED"
        if self.curl_exit_code != 0:
            return "CURL_ERROR (file intact)"
        return "OK"


def log(msg: str) -> None:
    print(msg, flush=True)


def find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_free_port_range(count: int) -> tuple[int, int]:
    for _ in range(200):
        start = find_free_tcp_port()
        sockets = []
        ok = True
        try:
            for p in range(start, start + count):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("127.0.0.1", p))
                except OSError:
                    s.close()
                    ok = False
                    break
                sockets.append(s)
            if ok:
                for s in sockets:
                    s.close()
                return start, start + count - 1
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError:
                    pass
    raise RuntimeError("could not find a free contiguous port range")


def build_sftpgo(dest: Path) -> Path:
    log(f"[setup] building sftpgo from {REPO_ROOT} -> {dest}")
    env = os.environ.copy()
    env.setdefault("CGO_ENABLED", "1")
    subprocess.run(
        ["go", "build", "-o", str(dest), "."],
        cwd=str(REPO_ROOT),
        env=env,
        check=True,
    )
    return dest


def generate_cert(cert_path: Path, key_path: Path) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "3650", "-nodes", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_user_dump(dump_path: Path, home_dir: Path) -> None:
    dump = {
        "users": [
            {
                "username": FTP_USER,
                "password": FTP_PASSWORD,
                "home_dir": str(home_dir),
                "status": 1,
                "permissions": {"/": ["*"]},
            }
        ],
        "groups": [],
        "folders": [],
        "admins": [],
        "api_keys": [],
        "shares": [],
        "event_actions": [],
        "event_rules": [],
        "roles": [],
        "ip_lists": [],
        "version": 17,
    }
    dump_path.write_text(json.dumps(dump))


def write_config(
    config_dir: Path,
    control_port: int,
    passive_start: int,
    passive_end: int,
    cert_path: Path,
    key_path: Path,
    db_path: Path,
    max_tls_version: int,
) -> None:
    config = {
        "common": {"upload_mode": 0},
        "httpd": {
            "bindings": [],
            "templates_path": str(REPO_ROOT / "templates"),
            "static_files_path": str(REPO_ROOT / "static"),
        },
        "smtp": {"templates_path": str(REPO_ROOT / "templates")},
        "ftpd": {
            "bindings": [
                {
                    "port": control_port,
                    "address": "127.0.0.1",
                    "apply_proxy_config": False,
                    "tls_mode": 1,
                    "min_tls_version": 12,
                    "max_tls_version": max_tls_version,
                    "force_passive_ip": "127.0.0.1",
                }
            ],
            "passive_port_range": {"start": passive_start, "end": passive_end},
            "certificate_file": str(cert_path),
            "certificate_key_file": str(key_path),
        },
        "data_provider": {
            "driver": "sqlite",
            "name": str(db_path),
        },
    }
    (config_dir / "sftpgo.json").write_text(json.dumps(config, indent=2))


def wait_for_port(port: int, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.1)
    raise RuntimeError(f"sftpgo did not start listening on port {port} within {timeout_s}s")


class SftpgoServer:
    def __init__(self, sftpgo_bin: Path, config_dir: Path, dump_path: Path, control_port: int, log_path: Path):
        self.log_file = open(log_path, "wb")
        self.proc = subprocess.Popen(
            [
                str(sftpgo_bin), "serve",
                "--config-dir", str(config_dir),
                "--loaddata-from", str(dump_path),
            ],
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_port(control_port)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log_file.close()


TLS_LINE_RE = re.compile(r"SSL connection using (TLSv[0-9.]+)")

# A few curl exit codes worth spelling out; see `man curl` (EXIT CODES).
CURL_EXIT_CODES = {
    18: "CURLE_PARTIAL_FILE (server did not send/receive all expected data)",
    28: "CURLE_OPERATION_TIMEDOUT",
    35: "CURLE_SSL_CONNECT_ERROR",
    55: "CURLE_SEND_ERROR (failed sending data to the peer)",
    56: "CURLE_RECV_ERROR (failure receiving data from the peer)",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_upload(
    curl_bin: Path,
    control_port: int,
    cert_path: Path,
    src_path: Path,
    remote_name: str,
    home_dir: Path,
    limit_rate: str,
    profile: str,
    repeat: int,
) -> AttemptResult:
    url = f"ftp://127.0.0.1:{control_port}/{remote_name}"
    cmd = [
        str(curl_bin), "-sS", "-v",
        "--ssl-reqd",
        "--cacert", str(cert_path),
        "-u", f"{FTP_USER}:{FTP_PASSWORD}",
        "--limit-rate", limit_rate,
        "--connect-timeout", "10",
        "--max-time", "60",
        "-T", str(src_path),
        url,
    ]
    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    elapsed = time.monotonic() - start

    negotiated = TLS_LINE_RE.findall(proc.stderr)

    error_msg = ""
    if proc.returncode != 0:
        known = CURL_EXIT_CODES.get(proc.returncode, "")
        tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
        error_msg = f"exit={proc.returncode} {known} :: {tail}"

    remote_path = home_dir / remote_name
    remote_exists = remote_path.is_file()
    remote_size = remote_path.stat().st_size if remote_exists else 0
    source_size = src_path.stat().st_size
    size_match = remote_exists and remote_size == source_size
    sha_match = size_match and sha256_file(remote_path) == sha256_file(src_path)

    return AttemptResult(
        profile=profile,
        curl_version=curl_bin.name,
        repeat=repeat,
        curl_exit_code=proc.returncode,
        curl_error=error_msg,
        negotiated_tls=negotiated,
        remote_exists=remote_exists,
        remote_size=remote_size,
        source_size=source_size,
        size_match=size_match,
        sha_match=sha_match,
        elapsed_s=elapsed,
    )


def discover_curl_binaries(curl_dir: Path) -> list[Path]:
    def version_key(p: Path) -> tuple:
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", p.name)
        return tuple(int(g) for g in m.groups()) if m else (0, 0, 0)

    binaries = sorted(
        (p for p in curl_dir.iterdir() if p.is_file() and os.access(p, os.X_OK) and p.name.startswith("curl-")),
        key=version_key,
    )
    if not binaries:
        raise SystemExit(
            f"no curl-<version> binaries found in {curl_dir}; "
            "see scripts/tls13-curl-repro/README.md"
        )
    return binaries


def print_matrix(results: list[AttemptResult]) -> None:
    header = f"{'profile':14} {'curl':12} {'#':>2} {'outcome':22} {'tls':10} {'size (got/want)':18} {'note'}"
    log(header)
    log("-" * len(header))
    for r in results:
        tls = r.negotiated_tls[-1] if r.negotiated_tls else "?"
        size = f"{r.remote_size}/{r.source_size}"
        note = r.curl_error if r.curl_exit_code != 0 else ""
        log(f"{r.profile:14} {r.curl_version:12} {r.repeat:>2} {r.outcome:22} {tls:10} {size:18} {note}")


def summarize(results: list[AttemptResult]) -> None:
    log("")
    log("Summary (worst outcome observed per profile/curl version, across repeats):")
    by_key: dict[tuple[str, str], list[AttemptResult]] = {}
    for r in results:
        by_key.setdefault((r.profile, r.curl_version), []).append(r)
    rank = {"OK": 0, "CURL_ERROR (file intact)": 1, "CURL_ERROR": 2, "MISSING": 3, "TRUNCATED": 4}
    for (profile, curl_version), attempts in sorted(by_key.items()):
        worst = max(attempts, key=lambda a: rank.get(a.outcome, 99))
        flag = "BUG REPRODUCED" if worst.outcome in ("TRUNCATED", "MISSING") else "ok"
        log(f"  {profile:14} {curl_version:12} -> {worst.outcome:22} [{flag}]")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--curl-dir", type=Path, default=DEFAULT_CURL_DIR,
                         help="directory containing curl-<version> binaries (default: %(default)s)")
    parser.add_argument("--sftpgo-bin", type=Path, default=None,
                         help="path to a pre-built sftpgo binary (default: build one)")
    parser.add_argument("--file-size-mb", type=int, default=24,
                         help="size of the random upload payload in MiB (default: %(default)s)")
    parser.add_argument("--limit-rate", type=str, default="2M",
                         help="curl --limit-rate value; a slower rate makes an in-flight tail at "
                              "close() more likely, which is what turns the RST into data loss "
                              "(default: %(default)s)")
    parser.add_argument("--repeat", type=int, default=3,
                         help="attempts per curl version on the 'default' (vulnerable) profile; "
                              "the 'capped-tls12' profile always runs once, since the mitigation "
                              "is not timing-dependent (default: %(default)s)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace for inspection")
    parser.add_argument("--json-out", type=Path, default=None, help="also write raw results as JSON")
    args = parser.parse_args()

    curl_binaries = discover_curl_binaries(args.curl_dir)
    log("[setup] curl binaries:")
    for b in curl_binaries:
        v = subprocess.run([str(b), "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        log(f"         {b.name}: {v}")

    workspace = Path(tempfile.mkdtemp(prefix="sftpgo-tls13-repro-"))
    log(f"[setup] workspace: {workspace}")

    sftpgo_bin = args.sftpgo_bin or build_sftpgo(workspace / "sftpgo")

    cert_path = workspace / "cert.pem"
    key_path = workspace / "key.pem"
    generate_cert(cert_path, key_path)

    src_path = workspace / "source.bin"
    with open(src_path, "wb") as f:
        f.write(os.urandom(args.file_size_mb * 1024 * 1024))
    log(f"[setup] generated {args.file_size_mb} MiB random source file: {src_path}")

    all_results: list[AttemptResult] = []

    try:
        for profile in PROFILES:
            log("")
            log(f"=== profile: {profile.name} ({profile.description}) ===")

            profile_dir = workspace / profile.name
            config_dir = profile_dir / "config"
            home_dir = profile_dir / "home"
            config_dir.mkdir(parents=True)
            home_dir.mkdir(parents=True)

            control_port = find_free_tcp_port()
            passive_start, passive_end = find_free_port_range(30)

            write_config(
                config_dir, control_port, passive_start, passive_end,
                cert_path, key_path, profile_dir / "sftpgo.db", profile.max_tls_version,
            )
            dump_path = profile_dir / "userdata.json"
            write_user_dump(dump_path, home_dir)

            server = SftpgoServer(sftpgo_bin, config_dir, dump_path, control_port, profile_dir / "sftpgo.log")
            log(f"[server] listening on 127.0.0.1:{control_port} (passive {passive_start}-{passive_end}), "
                f"max_tls_version={profile.max_tls_version or 'unrestricted'}")

            try:
                repeats = args.repeat if profile.max_tls_version == 0 else 1
                for curl_bin in curl_binaries:
                    for i in range(1, repeats + 1):
                        remote_name = f"{curl_bin.name}-{profile.name}-{i}.bin"
                        result = run_upload(
                            curl_bin, control_port, cert_path, src_path, remote_name,
                            home_dir, args.limit_rate, profile.name, i,
                        )
                        all_results.append(result)
                        log(f"  {curl_bin.name} attempt {i}/{repeats}: {result.outcome} "
                            f"(tls={result.negotiated_tls[-1] if result.negotiated_tls else '?'}, "
                            f"{result.elapsed_s:.2f}s)")
            finally:
                server.stop()
    finally:
        if args.keep:
            log(f"[cleanup] keeping workspace: {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)

    log("")
    print_matrix(all_results)
    summarize(all_results)

    if args.json_out:
        args.json_out.write_text(json.dumps([dataclasses.asdict(r) for r in all_results], indent=2))
        log(f"\n[out] wrote raw results to {args.json_out}")

    log(textwrap.dedent("""
        Notes:
          - This is a loopback, best-effort reproduction. TRUNCATED/MISSING on the
            'default' profile demonstrates the bug; OK on all curl versions for the
            'capped-tls12' profile demonstrates that forcing max_tls_version=12
            server-side sidesteps it regardless of client behavior.
          - A single non-TRUNCATED run for a known-buggy curl version is not proof
            the bug can't happen; re-run with --repeat higher or a lower --limit-rate
            if you want more confidence either way.
          - Empirically (see README "What we actually observed"), curl 7.88.1 did
            NOT reproduce the truncation against SFTPGo in this harness: strace shows
            it issues one non-blocking recv() on the data socket right before close(),
            which happens to drain SFTPGo's single NewSessionTicket (Go's crypto/tls
            sends exactly one per connection). OpenSSL-based servers such as vsftpd or
            ProFTPD send two tickets by default; a single incidental drain read would
            leave the second one unread, which is the more likely trigger in practice.
            Treat a clean run against SFTPGo as inconclusive, not as proof the client
            is safe against every FTPS server.
          - curl 8.21.0 has a separate, unrelated TLS-session-reuse regression on
            the data connection; SFTPGo OSS does not enforce session reuse, so it
            does not surface here.
    """))
    return 0


if __name__ == "__main__":
    sys.exit(main())
