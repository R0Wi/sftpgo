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
- `bin/curl-7.88.1`, `bin/curl-8.20.0`, `bin/curl-8.21.0`, `bin/curl-8.22.0`
  -- real curl binaries built from the official `curl.se` source tarballs
  for this repro:
  - **7.88.1** (Feb 2023): predates curl's 8.9.0 fix for graceful FTP
    data-connection shutdown.
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

Useful flags:

```
--file-size-mb N     size of the random upload payload (default 24)
--limit-rate RATE    curl --limit-rate value, e.g. 2M (default 2M)
--repeat N           attempts per curl version on the vulnerable profile (default 3)
--keep               keep the temp workspace (config, logs, pcap-able data) for inspection
--json-out PATH      also dump raw per-attempt results as JSON
--sftpgo-bin PATH    reuse an existing sftpgo binary instead of building one
```

The script runs two server profiles per invocation:

| profile        | `max_tls_version` | expected negotiated TLS |
|----------------|-------------------|--------------------------|
| `default`      | unset (`0`)       | 1.3 (today's shipped default) |
| `capped-tls12` | `12`               | 1.2 (the mitigation)     |

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

## Rebuilding the curl binaries

Built from the official source tarballs, statically linked against
libcurl (so the `curl` binary doesn't depend on the *system's* possibly
different libcurl.so) but dynamically against OpenSSL/zlib/libc:

```sh
for v in 7.88.1 8.20.0 8.21.0 8.22.0; do
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
