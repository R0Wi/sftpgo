# FTPS / TLS 1.3 upload-truncation repro harness

Accompanies the analysis of FTPS uploads failing with TLS 1.3 (client closes
the data connection without reading the server's post-handshake
`NewSessionTicket`, which on Linux turns `close()` into a RST that can
discard unacknowledged upload bytes). `repro.py` spins up a throwaway local
SFTPGo instance, uploads a file over explicit FTPS with several real curl
builds, and checks whether the server-side file matches the source.

It also exercises the mitigation added alongside this script:
`ftpd.bindings[].max_tls_version`, which lets an admin cap the negotiated
TLS version (e.g. to 1.2) server-side instead of waiting for every client to
be patched.

## Contents

- `repro.py` -- the test harness (stdlib-only, Python 3.9+).
- `bin/curl-7.69.1`, `bin/curl-7.88.1`, `bin/curl-8.20.0`, `bin/curl-8.21.0`,
  `bin/curl-8.22.0` -- real curl binaries built from the official `curl.se`
  source tarballs for this repro:
  - **7.69.1** (March 2020): squarely in the Yocto/Buildroot 7.6x range the
    analysis calls out as still shipping on 2020-2024 embedded BSPs. This is
    the version that actually reproduces the truncation in this harness --
    see "The vsftpd positive control" below.
  - **7.88.1** (Feb 2023): also predates curl's 8.9.0 fix, but does not
    reproduce the truncation here either (see "What we actually observed").
  - **8.20.0**: has the 8.9.0 fix (graceful shutdown, `close_notify` sent
    and drained before declaring the upload done).
  - **8.21.0**: same fix, but carries a separate, unrelated TLS
    session-reuse regression on the data connection (curl issue #22225).
  - **8.22.0**: current release; both the shutdown fix and the session-reuse
    regression are fixed.

  Built with `--disable-shared` against this build host's OpenSSL 3.0/zlib,
  then stripped, so each binary's only runtime dependencies are
  `libssl.so.3`, `libcrypto.so.3`, `libz.so.1`, `libc.so.6` and the dynamic
  linker -- present on essentially any modern glibc-based Linux amd64
  system (Ubuntu 22.04+/Debian 12+/Fedora/etc.). They are not fully static;
  see "Rebuilding the curl binaries" if you need that.

## Usage

```sh
python3 scripts/tls13-curl-repro/repro.py
```

Requires: Go toolchain (to build sftpgo), `openssl` CLI (to generate a
throwaway self-signed cert), and the bundled curl binaries. Everything runs
locally against `127.0.0.1`; nothing leaves the machine.

If `vsftpd` is installed and the script is running as root, it also runs two
vsftpd profiles (see "The vsftpd positive control" below) -- root is needed
because vsftpd authenticates local users through PAM/NSS against a real
system account, which the script creates and removes again
(`sftpgotlsrepro`). Skipped automatically, with a one-line message, if
either condition isn't met, or with `--skip-vsftpd`.

Useful flags:

```
--file-size-mb N     size of the random upload payload (default 24)
--limit-rate RATE    curl --limit-rate value for the SFTPGo profiles (default 2M)
--repeat N           attempts per curl version on the vulnerable profiles (default 3)
--keep               keep the temp workspace (config, logs, pcap-able data) for inspection
--json-out PATH      also dump raw per-attempt results as JSON
--sftpgo-bin PATH    reuse an existing sftpgo binary instead of building one
--skip-vsftpd        skip the vsftpd profiles even if available
```

The script runs up to four server profiles per invocation:

| profile             | server | TLS 1.3 allowed? | expected negotiated TLS |
|----------------------|--------|-------------------|--------------------------|
| `default`            | SFTPGo | yes (`max_tls_version` unset) | 1.3 |
| `capped-tls12`       | SFTPGo | no (`max_tls_version=12`)     | 1.2 |
| `vsftpd-default`      | vsftpd | yes (`ssl_tlsv13` at its compiled-in default) | 1.3 |
| `vsftpd-tls12-only`   | vsftpd | no (`ssl_tlsv13=NO`)          | 1.2 |

For each, it uploads to every bundled curl version and diffs the
server-side file against the source (size + SHA-256), and reports one of:
`OK`, `TRUNCATED`, `MISSING`, or `CURL_ERROR` (with curl's exit code and
last stderr line).

## What we actually observed

Running this harness against SFTPGo itself (Go's `crypto/tls`), **the
truncation did not reproduce even with curl 7.88.1**, across 20+ attempts at
varying file sizes and transfer rates. A representative run:

```
profile        curl          # outcome                tls        size (got/want)
----------------------------------------------------------------------------------------
default        curl-7.88.1   1 OK                     TLSv1.3    16777216/16777216
default        curl-7.88.1   2 OK                     TLSv1.3    16777216/16777216
default        curl-7.88.1   3 OK                     TLSv1.3    16777216/16777216
default        curl-8.20.0   1 OK                     TLSv1.3    16777216/16777216
default        curl-8.21.0   1 OK                     TLSv1.3    16777216/16777216
default        curl-8.22.0   1 OK                     TLSv1.3    16777216/16777216
capped-tls12   curl-7.88.1   1 OK                     TLSv1.2    16777216/16777216
capped-tls12   curl-8.20.0   1 OK                     TLSv1.2    16777216/16777216
capped-tls12   curl-8.21.0   1 OK                     TLSv1.2    16777216/16777216
capped-tls12   curl-8.22.0   1 OK                     TLSv1.2    16777216/16777216
```

We ran this down with `tcpdump` and `strace` rather than accept a silent
non-repro. Two independent findings explain it:

1. **`strace -e trace=network,close` on curl 7.88.1's data connection**
   shows, right before `close()`:
   ```
   recvfrom(7, "\27\3\3\0\213", 5, ...)      = 5      # TLS record header
   recvfrom(7, "...", 139, ...)              = 139    # the NewSessionTicket
   recvfrom(7, ..., 5, ...)                  = -1 EAGAIN
   close(7)                                  = 0
   ```
   curl 7.88.1 issues one non-blocking `recv()` on the data socket as part
   of its normal transfer-completion handling (no `SSL_shutdown()`, no
   `close_notify` -- that part matches the bug report). Since **Go's
   `crypto/tls` sends exactly one session ticket per connection**
   (`handshake_server_tls13.go`: "we only ever send one ticket per
   connection"), that single incidental read is enough to fully drain it,
   so the receive buffer is empty by the time `close()` runs and Linux
   sends a clean FIN instead of a RST.

   OpenSSL-based FTPS servers (vsftpd, ProFTPD) send **two** tickets by
   default. The same one-shot incidental read would drain only the first,
   leaving the second sitting unread -- which is the more likely trigger in
   practice, and matches the report's own note that the original curl bug
   reports and the Broadcom KB article were against vsftpd, not SFTPGo.

2. Packet captures (`tcpdump -i lo`) of a full-speed loopback transfer show
   the whole exchange -- handshake through the client's final `FIN` --
   completing in low single-digit milliseconds, with the server's ticket
   packet sometimes arriving a few hundred microseconds *after* the client
   had already sent FIN. On a real network (or even just a slower/loaded
   host), the ticket -- sent essentially back-to-back with the server's
   handshake `Finished` -- would already be sitting in the client's receive
   buffer well before the client finishes uploading and closes. Loopback
   timing is not representative here regardless of the ticket-count point
   above.

**Conclusion:** a clean run of this harness against SFTPGo is evidence that
*this specific mechanism, against a single-ticket Go TLS server, on this
host* didn't trigger -- not proof that a pre-8.9 curl client is safe to run
against FTPS servers in general, and not proof the underlying client bug
doesn't matter. The `capped-tls12` profile's results are the same
regardless of this nuance: forcing TLS 1.2 removes the post-handshake
message entirely, so there's nothing for any client, old or new, to fail to
drain.

If you want to try reproducing the truncation itself (not just validate the
mitigation), the more promising angles are: point `repro.py`'s upload at an
OpenSSL-based FTPS server instead of SFTPGo (two tickets), or run over an
actual higher-latency link rather than loopback.

## The vsftpd positive control

Following the angle above, `repro.py` also runs a stock vsftpd instance
(Debian/Ubuntu's shipped `/etc/vsftpd.conf`, with only `listen`,
`write_enable` and `ssl_enable` flipped on -- see `write_vsftpd_config()`).
This reliably reproduces the truncation:

```
=== profile: vsftpd-default (ssl_tlsv13 at its compiled-in default (YES): TLS 1.3 allowed) ===
  curl-7.69.1 attempt 1/3: TRUNCATED (tls=TLSv1.3, ...)
  curl-7.69.1 attempt 2/3: TRUNCATED (tls=TLSv1.3, ...)
  curl-7.69.1 attempt 3/3: TRUNCATED (tls=TLSv1.3, ...)
  curl-7.88.1 attempt 1/3: OK
  curl-8.20.0 attempt 1/3: OK
  curl-8.22.0 attempt 1/3: OK

vsftpd-default curl-7.69.1  1  TRUNCATED  TLSv1.3  18513920/20971520  exit=18 CURLE_PARTIAL_FILE :: curl: (18) server did not report OK, got 426

=== profile: vsftpd-tls12-only (ssl_tlsv13=NO) ===
  curl-7.69.1 attempt 1/1: OK (tls=TLSv1.2, ...)
```

curl **7.69.1** -- not 7.88.1 -- is the version that fails here: a 20 MiB
source lands 2-3 MiB short on disk, SHA-256 mismatched, curl exits 18
(`CURLE_PARTIAL_FILE`), vsftpd's control channel replies `426 Failure
reading network stream`. This is 100% reproducible (3/3, repeated across
many runs) at full upload speed. `vsftpd-tls12-only` fixes it for every
bundled curl version, confirming the same mitigation strategy
(`max_tls_version`/`ssl_tlsv13=NO`) works against a real second server
implementation, not just SFTPGo.

Two things worth calling out if you're comparing this to "What we actually
observed" above:

- **curl 7.88.1 does not reproduce it here either** -- only 7.69.1 does.
  So the deciding factor isn't simply "any curl before 8.9.0"; something
  curl's FTP/TLS handling already improved between 7.69 and 7.88 reduces,
  but doesn't eliminate, the exposure window before the real 8.9.0 fix.
  If you want to see this fail, use curl-7.69.1, not 7.88.1.
- **Full speed reproduces it; rate-limiting it away (this script's SFTPGo
  default, `--limit-rate 2M`) does not.** That's the opposite of the
  "slower is more likely to lose the race" intuition the rest of this
  document assumes for the SFTPGo case, so `repro.py` always runs the
  vsftpd profiles at full speed (`VSFTPD_UPLOAD_RATE`) regardless of
  `--limit-rate`. We did not fully chase down why the direction flips
  between the two servers; treat both directions as "it depends on the
  exact server and client implementation", not as a fixed rule.

curl 8.21.0's separate session-reuse regression also reproduces here (`curl:
(55) Send failure: Connection reset by peer`, both TLS versions) -- that's
the known, unrelated issue from curl issue #22225, not this bug; vsftpd
apparently is one of the "some backends" it affects, unlike SFTPGo OSS.

One implementation pitfall worth documenting in case you're extending this:
`tempfile.mkdtemp()` creates its directory `0700`. The vsftpd data
connection runs as the unprivileged throwaway system user, whose home lives
under that workspace; a `0700` ancestor blocks that user from traversing
into its own (`0755`) home directory after vsftpd drops privileges
post-login. This doesn't surface as a permission error -- it surfaces as a
garbled TLS record on the *control* connection (`OpenSSL SSL_read: ...
wrong version number`) immediately after `PASS`, which looks nothing like a
permissions problem and cost real time to track down via `strace`/`-v`
diffing against a working manual run. `main()` chmods the workspace to
`0755` right after creating it to avoid this.

## Why 550 and not 426 on SFTPGo

If you've hit this in production against SFTPGo, you may have seen FTP
reply **550** rather than vsftpd's **426** for the same kind of failed
upload. Both are the server's honest report of the same underlying event (a
reset/error reading the data connection); the reply code just depends on
which FTP server implementation is reporting it.

SFTPGo's FTP server is built on
[`fclairamb/ftpserverlib`](https://github.com/fclairamb/ftpserverlib). Its
generic transfer-completion handler (`clientHandler.TransferClose` in
`client_handler.go`) is what runs after *every* data transfer, success or
failure:

```go
switch {
case err == nil && errClose == nil:
    c.writeMessage(StatusClosingDataConn, "Closing transfer connection")
case errClose != nil:
    c.writeMessage(StatusActionNotTaken, fmt.Sprintf("Issue during transfer close: %v", errClose))
case err != nil:
    c.writeMessage(getErrorCode(err, StatusActionNotTaken), fmt.Sprintf("Issue during transfer: %v", err))
}
```

`getErrorCode(err, StatusActionNotTaken)` (`errors.go`) only overrides the
*default* code for two specific sentinel errors (storage-quota-exceeded,
disallowed filename); anything else -- including a plain `read: connection
reset by peer` from a truncated TLS 1.3 data connection -- falls through to
`StatusActionNotTaken`, which is **550** (`consts.go`:
`StatusActionNotTaken = 550 // RFC 959, 4.2.1`).

`ftpserverlib`'s **426** (`StatusTransferAborted`) exists too, but it's only
ever written from one place: the explicit `ABOR` command handler
(`handle_misc.go`, `handleABOR`). It is not used for a spontaneous
data-connection I/O error during a normal `STOR` -- vsftpd (a completely
separate C codebase) happens to hardcode 426 for exactly that case
(`"426 Failure reading network stream"`, as seen in this repro), but
SFTPGo's underlying library doesn't have an equivalent special case, so it
falls back to the generic 550.

In short: **550 from SFTPGo in production is consistent with this exact bug
class**, even though this harness can't force the underlying truncation to
happen against SFTPGo on this host (see "What we actually observed"). The
reply code difference is purely a difference in `ftpserverlib` vs. vsftpd's
error-to-reply-code mapping, not evidence of a different root cause. The
`max_tls_version=12` mitigation added alongside this script applies exactly
the same way regardless of which reply code you've seen.

## Rebuilding the curl binaries

Built from the official source tarballs, statically linked against
libcurl (so the `curl` binary doesn't depend on the *system's* possibly
different libcurl.so) but dynamically against OpenSSL/zlib/libc:

```sh
for v in 7.69.1 7.88.1 8.20.0 8.21.0 8.22.0; do
  curl -sSO "https://curl.se/download/curl-$v.tar.gz"
  tar xzf "curl-$v.tar.gz"
  (
    cd "curl-$v"
    ./configure --disable-shared --enable-static --with-openssl \
      --without-nghttp2 --without-libidn2 --without-libpsl \
      --without-brotli --without-zstd --without-libssh2 --without-libssh \
      --without-librtmp --without-gssapi --without-libgsasl \
      --disable-ldap --disable-ldaps --disable-manual
    make -j"$(nproc)"
  )
  cp "curl-$v/src/curl" "bin/curl-$v"
  strip --strip-all "bin/curl-$v"
done
```

Note `src/curl` is a libtool wrapper *script* (not the real binary) for a
`--disable-shared`-less (dynamic libcurl) build -- with `--disable-shared`
as above it's the real ELF binary directly. Verify with `file` and `ldd`
before trusting a rebuild.
