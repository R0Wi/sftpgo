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
3. If `vsftpd` is installed and this script is running as root, also starts a
   throwaway local vsftpd instance (stock /etc/vsftpd.conf with only
   listen/ssl_enable/write_enable flipped on -- see write_vsftpd_config()),
   once per "profile":
     - "vsftpd-default"     : ssl_tlsv13 left at its compiled-in default (YES)
     - "vsftpd-tls12-only"  : ssl_tlsv13=NO (vsftpd's own equivalent of the
                               SFTPGo max_tls_version=12 mitigation)
   Skipped with a clear message if vsftpd isn't installed or we're not root
   (creating/removing the throwaway local system user needs root).
4. For every curl binary in --curl-dir (one per bundled version) and every
   repeat, uploads a freshly generated random file over explicit FTPS,
   rate-limited to make an in-flight tail at close() likely, and compares
   the file the server actually wrote against the source (size + SHA-256).
5. Prints a result matrix and a plain-English summary.

This is a best-effort, timing-sensitive reproduction: it runs over loopback,
so whether a RST actually drops bytes depends on kernel buffering and
scheduling at the moment curl closes the data connection. --limit-rate and
--repeat exist to make the race easier to hit; a single "no truncation
observed" run for a known-buggy curl version is not proof the bug is fixed,
only that it didn't trigger this time.

In our own testing, the SFTPGo profiles did NOT reproduce the truncation with
any bundled curl version, including 7.88.1 and even 7.69.1 (see README.md,
"What we actually observed", for the strace/tcpdump evidence and why). The
vsftpd-default profile DOES reproduce it reliably with curl 7.69.1 (curl exit
18 / CURLE_PARTIAL_FILE, server replies "426 Failure reading network
stream", the file on disk is genuinely short and its checksum doesn't
match) -- curl 7.88.1 and later do not trigger it there either. So this
harness's positive control for "the bug is real and this harness can catch
it" is curl-7.69.1 against vsftpd-default; the SFTPGo profiles are a
negative result worth keeping (SFTPGo's own users have reported the same
underlying failure in production, just surfaced as FTP reply 550 instead of
vsftpd's 426 -- see README.md, "Why 550 and not 426 on SFTPGo", for the
ftpserverlib code path that explains the different reply code without
requiring the truncation to reproduce here). The max_tls_version=12 /
ssl_tlsv13=NO mitigations are unaffected by any of this and verify cleanly
in both harnesses.

Usage
-----
    python3 repro.py [--curl-dir bin] [--file-size-mb 24] [--limit-rate 2M]
                      [--repeat 3] [--keep] [--sftpgo-bin PATH] [--skip-vsftpd]
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

VSFTPD_SYSTEM_USER = "sftpgotlsrepro"
VSFTPD_PASSWORD = "VsftpdTls13Repro-Pwd1234!"
VSFTPD_PORT = 2121
VSFTPD_PASV_MIN = 41000
VSFTPD_PASV_MAX = 41050

# Unlike the SFTPGo profiles, the vsftpd positive control reproduces best at
# full speed, not rate-limited: empirically, a rate-limited transfer against
# vsftpd gives curl's incidental control-connection reads enough wall-clock
# time to also drain the data connection's ticket before close(), which
# avoids the bug. --limit-rate only applies to the SFTPGo profiles.
VSFTPD_UPLOAD_RATE = "1000M"


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
class VsftpdProfile:
    name: str
    tlsv13_enabled: bool
    description: str


VSFTPD_PROFILES = [
    VsftpdProfile("vsftpd-default", True, "ssl_tlsv13 at its compiled-in default (YES): TLS 1.3 allowed"),
    VsftpdProfile("vsftpd-tls12-only", False, "ssl_tlsv13=NO: vsftpd's own equivalent of max_tls_version=12"),
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


def vsftpd_unavailable_reason() -> str | None:
    """Returns None if we can run the vsftpd profiles, else a human-readable reason we can't."""
    if shutil.which("vsftpd") is None:
        return "vsftpd is not installed (apt-get install vsftpd on Debian/Ubuntu)"
    if os.geteuid() != 0:
        return "not running as root (needed to create/remove the throwaway local system user)"
    return None


def write_vsftpd_config(config_path: Path, home_dir: Path, cert_path: Path, key_path: Path, tlsv13_enabled: bool) -> None:
    """Builds a vsftpd.conf that is a minimal diff from the stock Debian/Ubuntu
    /etc/vsftpd.conf: only listen/listen_ipv6/write_enable/ssl_enable are
    flipped from their shipped defaults, plus a small block for running this
    one throwaway instance unprivileged and self-contained. Falls back to a
    bundled equivalent of the stock defaults if /etc/vsftpd.conf isn't
    present (e.g. a from-source vsftpd install)."""
    stock = Path("/etc/vsftpd.conf")
    if stock.is_file():
        content = stock.read_text()
        changes = {
            "listen=NO": "listen=YES",
            "listen_ipv6=YES": "listen_ipv6=NO",
            "#write_enable=YES": "write_enable=YES",
            "ssl_enable=NO": "ssl_enable=YES",
        }
        for old, new in changes.items():
            if old in content:
                content = content.replace(old, new, 1)
    else:
        # Equivalent of the stock Debian/Ubuntu defaults we rely on, in case
        # /etc/vsftpd.conf isn't there (e.g. vsftpd installed from source).
        content = textwrap.dedent("""\
            listen=YES
            listen_ipv6=NO
            anonymous_enable=NO
            local_enable=YES
            write_enable=YES
            dirmessage_enable=YES
            xferlog_enable=YES
            connect_from_port_20=YES
            secure_chroot_dir=/var/run/vsftpd/empty
            pam_service_name=vsftpd
            ssl_enable=YES
        """)

    extra = f"""
# --- added for this throwaway ad hoc TLS1.3 repro instance ---
listen_port={VSFTPD_PORT}
rsa_cert_file={cert_path}
rsa_private_key_file={key_path}
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv13={"YES" if tlsv13_enabled else "NO"}
pasv_enable=YES
pasv_address=127.0.0.1
pasv_min_port={VSFTPD_PASV_MIN}
pasv_max_port={VSFTPD_PASV_MAX}
seccomp_sandbox=NO
"""
    config_path.write_text(content + extra)


class VsftpdServer:
    """Starts a throwaway vsftpd instance against a throwaway local system user.

    Needs root: vsftpd's local-user auth goes through PAM/NSS against a real
    system account, so we create one (home_dir as its home) and remove it
    again in stop(). We never touch /etc/vsftpd.conf -- write_vsftpd_config()
    only reads it as a template.
    """

    def __init__(self, config_path: Path, home_dir: Path, log_path: Path):
        subprocess.run(["userdel", "-r", VSFTPD_SYSTEM_USER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["useradd", "-m", "-d", str(home_dir), "-s", "/bin/bash", VSFTPD_SYSTEM_USER],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["chpasswd"], input=f"{VSFTPD_SYSTEM_USER}:{VSFTPD_PASSWORD}\n",
            text=True, check=True,
        )
        home_dir.chmod(0o755)
        Path("/var/run/vsftpd/empty").mkdir(parents=True, exist_ok=True)
        Path("/var/run/vsftpd/empty").chmod(0o755)

        self.log_file = open(log_path, "wb")
        self.proc = subprocess.Popen(
            ["vsftpd", str(config_path)],
            stdout=self.log_file, stderr=subprocess.STDOUT,
        )
        try:
            wait_for_port(VSFTPD_PORT)
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
        subprocess.run(["userdel", "-r", VSFTPD_SYSTEM_USER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
    user: str = FTP_USER,
    password: str = FTP_PASSWORD,
    insecure: bool = False,
) -> AttemptResult:
    url = f"ftp://127.0.0.1:{control_port}/{remote_name}"
    cmd = [str(curl_bin), "-sS", "-v", "--ssl-reqd"]
    cmd += ["-k"] if insecure else ["--cacert", str(cert_path)]
    cmd += [
        "-u", f"{user}:{password}",
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
                         help="curl --limit-rate value for the SFTPGo profiles only; the vsftpd "
                              "profiles always run at full speed (see VSFTPD_UPLOAD_RATE), which is "
                              "empirically what reproduces the bug there (default: %(default)s)")
    parser.add_argument("--repeat", type=int, default=3,
                         help="attempts per curl version on the 'default' (vulnerable) profile; "
                              "the 'capped-tls12' profile always runs once, since the mitigation "
                              "is not timing-dependent (default: %(default)s)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace for inspection")
    parser.add_argument("--json-out", type=Path, default=None, help="also write raw results as JSON")
    parser.add_argument("--skip-vsftpd", action="store_true",
                         help="skip the vsftpd profiles even if vsftpd is installed and we're root")
    args = parser.parse_args()

    curl_binaries = discover_curl_binaries(args.curl_dir)
    log("[setup] curl binaries:")
    for b in curl_binaries:
        v = subprocess.run([str(b), "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        log(f"         {b.name}: {v}")

    workspace = Path(tempfile.mkdtemp(prefix="sftpgo-tls13-repro-"))
    # mkdtemp() defaults to 0700. The vsftpd profiles' data connection runs as
    # an unprivileged local system user whose home lives under here; a 0700
    # ancestor blocks that user from traversing into it after vsftpd drops
    # privileges post-login, even though the home dir itself is 0755 -- which
    # surfaces as a garbled/misparsed TLS control-connection response, not a
    # clean permission error. Keep the workspace world-traversable.
    workspace.chmod(0o755)
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

        skip_reason = "explicitly skipped (--skip-vsftpd)" if args.skip_vsftpd else vsftpd_unavailable_reason()
        if skip_reason:
            log("")
            log(f"=== skipping vsftpd profiles: {skip_reason} ===")
        else:
            for vprofile in VSFTPD_PROFILES:
                log("")
                log(f"=== profile: {vprofile.name} ({vprofile.description}) ===")

                profile_dir = workspace / vprofile.name
                home_dir = profile_dir / "home"
                profile_dir.mkdir(parents=True)

                config_path = profile_dir / "vsftpd.conf"
                write_vsftpd_config(config_path, home_dir, cert_path, key_path, vprofile.tlsv13_enabled)

                vserver = VsftpdServer(config_path, home_dir, profile_dir / "vsftpd.log")
                log(f"[server] listening on 127.0.0.1:{VSFTPD_PORT} (passive {VSFTPD_PASV_MIN}-{VSFTPD_PASV_MAX}), "
                    f"ssl_tlsv13={'YES' if vprofile.tlsv13_enabled else 'NO'}")

                try:
                    repeats = args.repeat if vprofile.tlsv13_enabled else 1
                    for curl_bin in curl_binaries:
                        for i in range(1, repeats + 1):
                            remote_name = f"{curl_bin.name}-{vprofile.name}-{i}.bin"
                            result = run_upload(
                                curl_bin, VSFTPD_PORT, cert_path, src_path, remote_name,
                                home_dir, VSFTPD_UPLOAD_RATE, vprofile.name, i,
                                user=VSFTPD_SYSTEM_USER, password=VSFTPD_PASSWORD, insecure=True,
                            )
                            all_results.append(result)
                            log(f"  {curl_bin.name} attempt {i}/{repeats}: {result.outcome} "
                                f"(tls={result.negotiated_tls[-1] if result.negotiated_tls else '?'}, "
                                f"{result.elapsed_s:.2f}s)")
                finally:
                    vserver.stop()
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
          - This is a loopback, best-effort reproduction. TRUNCATED/MISSING on a
            '*-default'/'default' profile demonstrates the bug; OK on all curl
            versions for a 'capped-tls12'/'*-tls12-only' profile demonstrates that
            forcing TLS 1.2 (server-side) sidesteps it regardless of client behavior.
          - A single non-TRUNCATED run for a known-buggy curl version is not proof
            the bug can't happen; re-run with --repeat higher or a lower --limit-rate
            if you want more confidence either way.
          - The SFTPGo profiles ('default'/'capped-tls12') did not reproduce the
            truncation in our testing, with any bundled curl version -- see README.md
            ("What we actually observed") for why. Treat a clean run there as
            inconclusive, not as proof no SFTPGo user can hit this: it can, and it
            has been reported in production, just surfacing as FTP reply 550 instead
            of vsftpd's 426 (see README.md, "Why 550 and not 426 on SFTPGo").
          - The vsftpd profiles ('vsftpd-default'/'vsftpd-tls12-only') are this
            harness's positive control: curl-7.69.1 reliably reproduces the
            truncation against vsftpd-default (curl exit 18 / CURLE_PARTIAL_FILE,
            "426 Failure reading network stream"), and vsftpd-tls12-only reliably
            fixes it for every bundled curl version, same as SFTPGo's
            max_tls_version=12. curl 7.88.1 and later do not trigger it against
            vsftpd either -- 7.69.1 is the version to use if you want to see this
            fail.
          - curl 8.21.0 has a separate, unrelated TLS-session-reuse regression on
            the data connection; SFTPGo OSS does not enforce session reuse, so it
            does not surface here.
    """))
    return 0


if __name__ == "__main__":
    sys.exit(main())
