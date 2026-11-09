# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import posixpath
import random
import re
import time
from http.client import responses
from urllib import parse

import treq
from twisted.internet import error
from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger
from twisted.python import failure
from twisted.web.iweb import UNKNOWN_LENGTH

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.download import (
    BlockedAddress,
    UnreachableAddress,
    capture_download,
    outbound_rate_limiter,
    report_download_failure,
)
from cowrie.core.network import (
    DownloadLimitExceeded,
    abort_body,
    communication_allowed,
)
from cowrie.shell.command import HoneyPotCommand

commands = {}

curl_rate_limiter = outbound_rate_limiter("curl")

CURL_HELP = """Usage: curl [options...] <url>
Options: (H) means HTTP/HTTPS only, (F) means FTP only
     --anyauth       Pick "any" authentication method (H)
 -a, --append        Append to target file when uploading (F/SFTP)
     --basic         Use HTTP Basic Authentication (H)
     --cacert FILE   CA certificate to verify peer against (SSL)
     --capath DIR    CA directory to verify peer against (SSL)
 -E, --cert CERT[:PASSWD] Client certificate file and password (SSL)
     --cert-type TYPE Certificate file type (DER/PEM/ENG) (SSL)
     --ciphers LIST  SSL ciphers to use (SSL)
     --compressed    Request compressed response (using deflate or gzip)
 -K, --config FILE   Specify which config file to read
     --connect-timeout SECONDS  Maximum time allowed for connection
 -C, --continue-at OFFSET  Resumed transfer offset
 -b, --cookie STRING/FILE  String or file to read cookies from (H)
 -c, --cookie-jar FILE  Write cookies to this file after operation (H)
     --create-dirs   Create necessary local directory hierarchy
     --crlf          Convert LF to CRLF in upload
     --crlfile FILE  Get a CRL list in PEM format from the given file
 -d, --data DATA     HTTP POST data (H)
     --data-ascii DATA  HTTP POST ASCII data (H)
     --data-binary DATA  HTTP POST binary data (H)
     --data-urlencode DATA  HTTP POST data url encoded (H)
     --delegation STRING GSS-API delegation permission
     --digest        Use HTTP Digest Authentication (H)
     --disable-eprt  Inhibit using EPRT or LPRT (F)
     --disable-epsv  Inhibit using EPSV (F)
 -D, --dump-header FILE  Write the headers to this file
     --egd-file FILE  EGD socket path for random data (SSL)
     --engine ENGINGE  Crypto engine (SSL). "--engine list" for list
 -f, --fail          Fail silently (no output at all) on HTTP errors (H)
 -F, --form CONTENT  Specify HTTP multipart POST data (H)
     --form-string STRING  Specify HTTP multipart POST data (H)
     --ftp-account DATA  Account data string (F)
     --ftp-alternative-to-user COMMAND  String to replace "USER [name]" (F)
     --ftp-create-dirs  Create the remote dirs if not present (F)
     --ftp-method [MULTICWD/NOCWD/SINGLECWD] Control CWD usage (F)
     --ftp-pasv      Use PASV/EPSV instead of PORT (F)
 -P, --ftp-port ADR  Use PORT with given address instead of PASV (F)
     --ftp-skip-pasv-ip Skip the IP address for PASV (F)
     --ftp-pret      Send PRET before PASV (for drftpd) (F)
     --ftp-ssl-ccc   Send CCC after authenticating (F)
     --ftp-ssl-ccc-mode ACTIVE/PASSIVE  Set CCC mode (F)
     --ftp-ssl-control Require SSL/TLS for ftp login, clear for transfer (F)
 -G, --get           Send the -d data with a HTTP GET (H)
 -g, --globoff       Disable URL sequences and ranges using {} and []
 -H, --header LINE   Custom header to pass to server (H)
 -I, --head          Show document info only
 -h, --help          This help text
     --hostpubmd5 MD5  Hex encoded MD5 string of the host public key. (SSH)
 -0, --http1.0       Use HTTP 1.0 (H)
     --ignore-content-length  Ignore the HTTP Content-Length header
 -i, --include       Include protocol headers in the output (H/F)
 -k, --insecure      Allow connections to SSL sites without certs (H)
     --interface INTERFACE  Specify network interface/address to use
 -4, --ipv4          Resolve name to IPv4 address
 -6, --ipv6          Resolve name to IPv6 address
 -j, --junk-session-cookies Ignore session cookies read from file (H)
     --keepalive-time SECONDS  Interval between keepalive probes
     --key KEY       Private key file name (SSL/SSH)
     --key-type TYPE Private key file type (DER/PEM/ENG) (SSL)
     --krb LEVEL     Enable Kerberos with specified security level (F)
     --libcurl FILE  Dump libcurl equivalent code of this command line
     --limit-rate RATE  Limit transfer speed to this rate
 -l, --list-only     List only names of an FTP directory (F)
     --local-port RANGE  Force use of these local port numbers
 -L, --location      Follow redirects (H)
     --location-trusted like --location and send auth to other hosts (H)
 -M, --manual        Display the full manual
     --mail-from FROM  Mail from this address
     --mail-rcpt TO  Mail to this receiver(s)
     --mail-auth AUTH  Originator address of the original email
     --max-filesize BYTES  Maximum file size to download (H/F)
     --max-redirs NUM  Maximum number of redirects allowed (H)
 -m, --max-time SECONDS  Maximum time allowed for the transfer
     --negotiate     Use HTTP Negotiate Authentication (H)
 -n, --netrc         Must read .netrc for user name and password
     --netrc-optional Use either .netrc or URL; overrides -n
     --netrc-file FILE  Set up the netrc filename to use
 -N, --no-buffer     Disable buffering of the output stream
     --no-keepalive  Disable keepalive use on the connection
     --no-sessionid  Disable SSL session-ID reusing (SSL)
     --noproxy       List of hosts which do not use proxy
     --ntlm          Use HTTP NTLM authentication (H)
 -o, --output FILE   Write output to <file> instead of stdout
     --pass PASS     Pass phrase for the private key (SSL/SSH)
     --post301       Do not switch to GET after following a 301 redirect (H)
     --post302       Do not switch to GET after following a 302 redirect (H)
     --post303       Do not switch to GET after following a 303 redirect (H)
 -#, --progress-bar  Display transfer progress as a progress bar
     --proto PROTOCOLS  Enable/disable specified protocols
     --proto-redir PROTOCOLS  Enable/disable specified protocols on redirect
 -x, --proxy [PROTOCOL://]HOST[:PORT] Use proxy on given port
     --proxy-anyauth Pick "any" proxy authentication method (H)
     --proxy-basic   Use Basic authentication on the proxy (H)
     --proxy-digest  Use Digest authentication on the proxy (H)
     --proxy-negotiate Use Negotiate authentication on the proxy (H)
     --proxy-ntlm    Use NTLM authentication on the proxy (H)
 -U, --proxy-user USER[:PASSWORD]  Proxy user and password
     --proxy1.0 HOST[:PORT]  Use HTTP/1.0 proxy on given port
 -p, --proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)
     --pubkey KEY    Public key file name (SSH)
 -Q, --quote CMD     Send command(s) to server before transfer (F/SFTP)
     --random-file FILE  File for reading random data from (SSL)
 -r, --range RANGE   Retrieve only the bytes within a range
     --raw           Do HTTP "raw", without any transfer decoding (H)
 -e, --referer       Referer URL (H)
 -J, --remote-header-name Use the header-provided filename (H)
 -O, --remote-name   Write output to a file named as the remote file
     --remote-name-all Use the remote file name for all URLs
 -R, --remote-time   Set the remote file's time on the local output
 -X, --request COMMAND  Specify request command to use
     --resolve HOST:PORT:ADDRESS  Force resolve of HOST:PORT to ADDRESS
     --retry NUM   Retry request NUM times if transient problems occur
     --retry-delay SECONDS When retrying, wait this many seconds between each
     --retry-max-time SECONDS  Retry only within this period
 -S, --show-error    Show error. With -s, make curl show errors when they occur
 -s, --silent        Silent mode. Don't output anything
     --socks4 HOST[:PORT]  SOCKS4 proxy on given host + port
     --socks4a HOST[:PORT]  SOCKS4a proxy on given host + port
     --socks5 HOST[:PORT]  SOCKS5 proxy on given host + port
     --socks5-hostname HOST[:PORT] SOCKS5 proxy, pass host name to proxy
     --socks5-gssapi-service NAME  SOCKS5 proxy service name for gssapi
     --socks5-gssapi-nec  Compatibility with NEC SOCKS5 server
 -Y, --speed-limit RATE  Stop transfers below speed-limit for 'speed-time' secs
 -y, --speed-time SECONDS  Time for trig speed-limit abort. Defaults to 30
     --ssl           Try SSL/TLS (FTP, IMAP, POP3, SMTP)
     --ssl-reqd      Require SSL/TLS (FTP, IMAP, POP3, SMTP)
 -2, --sslv2         Use SSLv2 (SSL)
 -3, --sslv3         Use SSLv3 (SSL)
     --ssl-allow-beast Allow security flaw to improve interop (SSL)
     --stderr FILE   Where to redirect stderr. - means stdout
     --tcp-nodelay   Use the TCP_NODELAY option
 -t, --telnet-option OPT=VAL  Set telnet option
     --tftp-blksize VALUE  Set TFTP BLKSIZE option (must be >512)
 -z, --time-cond TIME  Transfer based on a time condition
 -1, --tlsv1         Use TLSv1 (SSL)
     --trace FILE    Write a debug trace to the given file
     --trace-ascii FILE  Like --trace but without the hex output
     --trace-time    Add time stamps to trace/verbose output
     --tr-encoding   Request compressed transfer encoding (H)
 -T, --upload-file FILE  Transfer FILE to destination
     --url URL       URL to work with
 -B, --use-ascii     Use ASCII/text transfer
 -u, --user USER[:PASSWORD]  Server user and password
     --tlsuser USER  TLS username
     --tlspassword STRING TLS password
     --tlsauthtype STRING  TLS authentication type (default SRP)
 -A, --user-agent STRING  User-Agent to send to server (H)
 -v, --verbose       Make the operation more talkative
 -V, --version       Show version number and quit
 -w, --write-out FORMAT  What to output after completion
     --xattr        Store metadata in extended file attributes
 -q                 If used as the first parameter disables .curlrc
 """


# QPot: curl's own option parser (tool_getparam.c) with the options scripts and droppers use, its
#   messages per release, the exit codes of libcurl, and what a connection to an address the honeypot
#   never contacts does: Cowrie's took only -L -s -h -o -I -O, so the bait's own `curl -fsS -m 10
#   --retry 3 URL` ended in "option -f not recognized", and an address said "Could not resolve host".
#   What reaches the network is unchanged: one GET (HEAD for -I) of the first URL, as before, through
#   the same rate limit, address check and download capture; -d, -H, -X, -u ... are taken but the
#   request stays the one Cowrie sent; retries and redirects are not fetched again.

# curl of each release (the package of its archive)
QPOT_CURL_RELEASES = {("ubuntu", 24): (8, 5, 0), ("ubuntu", 22): (7, 81, 0), ("debian", 13): (8, 14, 1),
                      ("debian", 12): (7, 88, 1), ("rhel", 9): (7, 76, 1), ("centos", 7): (7, 29, 0)}
# the release whose texts were recorded (curl 8.14.1 of Debian 13): any persona curl is not known for
QPOT_CURL_RECORDED = (8, 14, 1)

# what `curl --version` prints: the first line's libraries after libcurl (OpenSSL's from the persona),
#   the release date and the protocols and features lines
QPOT_CURL_BUILDS = {
    (8, 14, 1): ("zlib/1.3.1 brotli/1.1.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.2 libssh2/1.11.1 nghttp2/1.64.0 "
                 "nghttp3/1.8.0 librtmp/2.3 OpenLDAP/2.6.10", "2025-06-04",
                 "dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtmp "
                 "rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss",
                 "alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz "
                 "NTLM PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd"),
    (8, 5, 0): ("zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) "
                "libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.7", "2023-12-06",
                "dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp "
                "scp sftp smb smbs smtp smtps telnet tftp",
                "alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM "
                "PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd"),
    (7, 88, 1): ("zlib/1.2.13 brotli/1.0.9 zstd/1.5.4 libidn2/2.3.3 libpsl/0.21.2 (+libidn2/2.3.3) "
                 "libssh2/1.10.0 nghttp2/1.52.0 librtmp/2.3 OpenLDAP/2.5.13", "2023-02-20",
                 "dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp "
                 "scp sftp smb smbs smtp smtps telnet tftp",
                 "alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM "
                 "NTLM_WB PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd"),
    (7, 81, 0): ("zlib/1.2.11 brotli/1.0.9 zstd/1.4.8 libidn2/2.3.2 libpsl/0.21.0 (+libidn2/2.3.2) "
                 "libssh/0.9.6/openssl/zlib nghttp2/1.43.0 librtmp/2.3 OpenLDAP/2.5.11", "2022-01-05",
                 "dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp "
                 "scp sftp smb smbs smtp smtps telnet tftp",
                 "alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM "
                 "NTLM_WB PSL SPNEGO SSL TLS-SRP UnixSockets zstd"),
    (7, 76, 1): ("zlib/1.2.11 brotli/1.0.9 libidn2/2.3.0 libpsl/0.21.1 (+libidn2/2.3.0) "
                 "libssh/0.10.4/openssl/zlib nghttp2/1.43.0", "2021-03-31",
                 "dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp "
                 "smb smbs smtp smtps telnet tftp",
                 "alt-svc AsynchDNS brotli GSS-API HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL "
                 "SPNEGO SSL TLS-SRP UnixSockets"),
    (7, 29, 0): ("NSS/3.53.1 zlib/1.2.7 libidn/1.28 libssh2/1.8.0", "",
                 "dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 pop3s rtsp scp sftp smtp smtps "
                 "telnet tftp ",
                 "AsynchDNS GSS-API IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB SPNEGO SSL UnixSockets"),
}

# options of curl's tool_getparam.c: long name -> (short letter, kind, since); kind is "bool", "text",
#   "seconds" (a decimal number of seconds) or "count" (a whole number >= 0)
QPOT_CURL_OPTIONS = {
    "fail": ("f", "bool", None), "silent": ("s", "bool", None), "show-error": ("S", "bool", None),
    "max-time": ("m", "seconds", None), "connect-timeout": (None, "seconds", None),
    "retry": (None, "count", None), "retry-delay": (None, "count", None), "retry-max-time": (None, "count", None),
    "retry-connrefused": (None, "bool", (7, 52, 0)), "retry-all-errors": (None, "bool", (7, 71, 0)),
    "insecure": ("k", "bool", None), "location": ("L", "bool", None), "location-trusted": (None, "bool", None),
    "output": ("o", "text", None), "remote-name": ("O", "bool", None), "remote-name-all": (None, "bool", None),
    "header": ("H", "text", None), "data": ("d", "text", None), "data-raw": (None, "text", (7, 43, 0)),
    "data-binary": (None, "text", None), "data-ascii": (None, "text", None), "data-urlencode": (None, "text", None),
    "request": ("X", "text", None), "user": ("u", "text", None), "user-agent": ("A", "text", None),
    "write-out": ("w", "text", None), "head": ("I", "bool", None), "help": ("h", "bool", None),
    "version": ("V", "bool", None), "verbose": ("v", "bool", None), "include": ("i", "bool", None),
    "referer": ("e", "text", None), "cookie": ("b", "text", None), "cookie-jar": ("c", "text", None),
    "form": ("F", "text", None), "form-string": (None, "text", None), "upload-file": ("T", "text", None),
    "range": ("r", "text", None), "continue-at": ("C", "text", None), "dump-header": ("D", "text", None),
    "proxy": ("x", "text", None), "proxy-user": ("U", "text", None), "noproxy": (None, "text", None),
    "config": ("K", "text", None), "cert": ("E", "text", None), "cacert": (None, "text", None),
    "capath": (None, "text", None), "key": (None, "text", None), "pass": (None, "text", None),
    "ciphers": (None, "text", None), "interface": (None, "text", None), "resolve": (None, "text", None),
    "connect-to": (None, "text", None), "url": (None, "text", None), "max-redirs": (None, "text", None),
    "max-filesize": (None, "text", None), "limit-rate": (None, "text", None), "speed-time": ("y", "text", None),
    "speed-limit": ("Y", "text", None), "time-cond": ("z", "text", None), "keepalive-time": (None, "text", None),
    "local-port": (None, "text", None), "output-dir": (None, "text", (7, 73, 0)), "stderr": (None, "text", None),
    "trace": (None, "text", None), "trace-ascii": (None, "text", None), "unix-socket": (None, "text", None),
    "oauth2-bearer": (None, "text", None), "socks5": (None, "text", None), "socks5-hostname": (None, "text", None),
    "socks4": (None, "text", None), "socks4a": (None, "text", None), "proto": (None, "text", None),
    "quote": ("Q", "text", None), "ftp-port": ("P", "text", None), "telnet-option": ("t", "text", None),
    "json": (None, "text", (7, 82, 0)), "dns-servers": (None, "text", None), "pinnedpubkey": (None, "text", None),
    "compressed": (None, "bool", None), "create-dirs": (None, "bool", None), "get": ("G", "bool", None),
    "globoff": ("g", "bool", None), "http1.0": ("0", "bool", None), "http1.1": (None, "bool", None),
    "http2": (None, "bool", None), "ipv4": ("4", "bool", None), "ipv6": ("6", "bool", None),
    "no-buffer": ("N", "bool", None), "keepalive": (None, "bool", None), "progress-meter": (None, "bool", (7, 67, 0)),
    "sessionid": (None, "bool", None), "progress-bar": ("#", "bool", None), "raw": (None, "bool", None),
    "ssl": (None, "bool", None), "ssl-reqd": (None, "bool", None), "tcp-nodelay": (None, "bool", None),
    "tlsv1": ("1", "bool", None), "tlsv1.2": (None, "bool", None), "tlsv1.3": (None, "bool", None),
    "sslv2": ("2", "bool", None), "sslv3": ("3", "bool", None), "path-as-is": (None, "bool", None),
    "proxytunnel": ("p", "bool", None), "remote-time": ("R", "bool", None), "basic": (None, "bool", None),
    "digest": (None, "bool", None), "ntlm": (None, "bool", None), "negotiate": (None, "bool", None),
    "anyauth": (None, "bool", None), "junk-session-cookies": ("j", "bool", None),
    "remote-header-name": ("J", "bool", None), "list-only": ("l", "bool", None), "append": ("a", "bool", None),
    "netrc": ("n", "bool", None), "netrc-optional": (None, "bool", None), "manual": ("M", "bool", None),
    "use-ascii": ("B", "bool", None), "xattr": (None, "bool", None), "disable": ("q", "bool", None),
    "parallel": ("Z", "bool", (7, 66, 0)), "fail-with-body": (None, "bool", (7, 76, 0)),
    "fail-early": (None, "bool", None), "post301": (None, "bool", None), "post302": (None, "bool", None),
    "post303": (None, "bool", None), "crlf": (None, "bool", None), "ftp-pasv": (None, "bool", None),
    "ftp-create-dirs": (None, "bool", None), "tr-encoding": (None, "bool", None), "styled-output": (None, "bool", None),
    "ignore-content-length": (None, "bool", None), "trace-time": (None, "bool", None),
    "proxy-insecure": (None, "bool", None), "http0.9": (None, "bool", None), "alpn": (None, "bool", None),
}
QPOT_CURL_SHORT = {short: name for name, (short, _, _) in QPOT_CURL_OPTIONS.items() if short}
# options that are only ever turned off with --no- (--no-keepalive, --no-progress-meter ...)
QPOT_CURL_NEGATED = {"keepalive", "progress-meter", "sessionid", "buffer", "alpn"}
QPOT_CURL_TRY = "curl: try 'curl --help' or 'curl --manual' for more information\n"
# a URL list or a header set is the attacker's to write: so many are read at most
QPOT_CURL_MAX_ARGS = 1024
QPOT_CURL_MAX_RETRIES = 1000
# the HTTP codes curl's --retry takes as transient (tool_operate.c)
QPOT_CURL_TRANSIENT = (408, 429, 500, 502, 503, 504)
# the kernel's SYN retries (net.ipv4.tcp_syn_retries 6) give up after 127 s, as for ssh
QPOT_KERNEL_TIMEOUT = 127


class QpotCurlUsage(Exception):
    """A command line curl refuses: its message, exit status 2."""


def qpot_curl_number(arg: str, value: str, kind: str) -> float:
    """The value of a numeric option, as curl's str2udouble/str2unum read it."""
    if kind == "count":
        if re.fullmatch(r"-[0-9]+", value or ""):
            raise QpotCurlUsage(f"curl: option {arg}: expected a positive numerical parameter\n")
        if not re.fullmatch(r"[0-9]{1,9}", value or ""):
            raise QpotCurlUsage(f"curl: option {arg}: expected a proper numerical parameter\n")
        return int(value)
    if not re.fullmatch(r"[0-9]{1,9}(\.[0-9]{0,9})?|\.[0-9]{1,9}", value or ""):
        raise QpotCurlUsage(f"curl: option {arg}: expected a proper numerical parameter\n")
    return float(value)


def qpot_curl_args(args: list[str], version: tuple) -> tuple[dict, list[str]]:
    """(options, URLs) of curl's command line: short options together (-fsSL), a parameter attached
    (-o/dev/null) or in the next word, long options whole (no abbreviations, no --opt=value), --no- for
    the switches. QpotCurlUsage for what curl refuses, with curl's message."""
    opts: dict = {"header": [], "data": []}
    urls: list[str] = []
    words = list(args[:QPOT_CURL_MAX_ARGS])
    i = 0

    def take(arg: str, name: str, kind: str, attached: str | None) -> None:
        nonlocal i
        if kind == "bool":
            opts[name] = True
            return
        if attached:
            value = attached
        elif i < len(words):
            value = words[i]
            i += 1
        else:
            raise QpotCurlUsage(f"curl: option {arg}: requires parameter\n")
        if kind in ("seconds", "count"):
            opts[name] = qpot_curl_number(arg, value, kind)
        elif name in ("header", "data"):
            opts[name].append(value)
        else:
            opts[name] = value

    def known(name: str) -> tuple | None:
        entry = QPOT_CURL_OPTIONS.get(name)
        if entry is None or (entry[2] is not None and version < entry[2]):
            return None
        return entry

    ended = False
    while i < len(words):
        arg = words[i]
        i += 1
        if ended or not arg.startswith("-") or arg == "-":
            urls.append(arg)
            continue
        if arg == "--":
            ended = True
            continue
        if arg.startswith("--"):
            name = arg[2:]
            entry = known(name)
            if entry is None and name.startswith("no-"):
                base = known(name[3:])
                if base is not None and base[1] == "bool":
                    opts[name[3:]] = False
                    continue
                if name[3:] in QPOT_CURL_NEGATED:
                    continue
            if entry is None:
                raise QpotCurlUsage(f"curl: option {arg}: is unknown\n")
            take(arg, name, entry[1], None)
            continue
        letters = arg[1:]
        for j, letter in enumerate(letters):
            name = QPOT_CURL_SHORT.get(letter)
            entry = known(name) if name else None
            if entry is None:
                raise QpotCurlUsage(f"curl: option {arg}: is unknown\n")
            if entry[1] != "bool":
                take(arg, name, entry[1], letters[j + 1:] or None)
                break
            opts[name] = True
    if opts.get("url"):
        urls.insert(0, opts["url"])
    return opts, urls


# --write-out: the variables curl knows; a value the transfer did not set reads as curl prints it then
QPOT_CURL_WRITE_VARS = ("content_type", "errormsg", "exitcode", "filename_effective", "ftp_entry_path",
                        "http_code", "http_connect", "http_version", "local_ip", "local_port", "method",
                        "num_connects", "num_headers", "num_redirects", "proxy_ssl_verify_result",
                        "redirect_url", "referer", "remote_ip", "remote_port", "response_code", "scheme",
                        "size_download", "size_header", "size_request", "size_upload", "speed_download",
                        "speed_upload", "ssl_verify_result", "time_appconnect", "time_connect",
                        "time_namelookup", "time_pretransfer", "time_redirect", "time_starttransfer",
                        "time_total", "url", "url_effective", "urlnum", "onerror", "json", "certs",
                        "num_certs", "conn_id", "xfer_id", "num_retries")
QPOT_CURL_WRITE_MAX = 65536


def qpot_curl_write_out(fmt: str, values: dict) -> tuple[str, str, list[str]]:
    """(text for stdout, text for stderr, warnings) of a --write-out format: %{var}, %%, \\n \\r \\t,
    %{stdout} and %{stderr} switching where the rest goes; an unknown variable is warned about and left
    out, an unterminated %{ kept as written."""
    out, err, warnings = [], [], []
    target = out
    i, n = 0, min(len(fmt), QPOT_CURL_WRITE_MAX)
    while i < n:
        c = fmt[i]
        if c == "%" and fmt.startswith("%%", i):
            target.append("%")
            i += 2
        elif c == "%" and fmt.startswith("%{", i):
            end = fmt.find("}", i + 2, min(n, i + 2 + 64))
            if end < 0:
                target.append("%{")
                i += 2
                continue
            name = fmt[i + 2:end]
            i = end + 1
            if name == "stdout":
                target = out
            elif name == "stderr":
                target = err
            elif name in QPOT_CURL_WRITE_VARS:
                target.append(str(values.get(name, "")))
            else:
                warnings.append(f"curl: unknown --write-out variable: '{name}'\n")
        elif c == "\\" and i + 1 < n and fmt[i + 1] in "nrt\\":
            target.append({"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}[fmt[i + 1]])
            i += 2
        else:
            target.append(c)
            i += 1
    return "".join(out), "".join(err), warnings


def qpot_curl_failure(version: tuple, kind: str, host: str, port: int, millis: int) -> tuple[int, str]:
    """(exit status, message) of a transfer that failed to connect, as the release's curl says it:
    kind is refused, timeout (curl's own -m or --connect-timeout ran out), kernel (the kernel gave up on
    the SYNs), unresolved."""
    if kind == "unresolved":
        return 6, f"Could not resolve host: {host}" + ("; Unknown error" if version < (7, 30, 0) else "")
    if kind == "timeout":
        return 28, f"Connection timed out after {millis} milliseconds"
    reason = "Connection refused" if kind == "refused" else "Connection timed out"
    # connect.c: 7.29 answers 7 for any failed connect, 7.76.1 and later 28 when the kernel timed out
    code = 28 if kind == "kernel" and version >= (7, 30, 0) else 7
    if version < (7, 30, 0):
        return code, f"Failed connect to {host}:{port}; {reason}"
    if version < (7, 78, 0):
        return code, f"Failed to connect to {host} port {port}: {reason}"
    if version < (7, 87, 0):
        return code, f"Failed to connect to {host} port {port} after {millis} ms: {reason}"
    word = "Couldn't" if version < (8, 10, 0) else "Could not"
    return code, f"Failed to connect to {host} port {port} after {millis} ms: {word} connect to server"


def qpot_curl_warning(text: str) -> str:
    """warnf of curl's tool_msgs.c: "Warning: " before each piece of at most 70 characters, cut after
    the last blank that fits (the blank ends the line), or at 70 where none does."""
    width, out = 79 - len("Warning: "), []
    while text:
        if len(text) > width:
            cut = width - 1
            while cut and text[cut] not in " \t":
                cut -= 1
            cut = cut or width - 1
            out.append("Warning: " + text[:cut + 1] + "\n")
            text = text[cut + 1:]
        else:
            out.append("Warning: " + text + "\n")
            text = ""
    return "".join(out)


def qpot_curl_retry_warning(version: tuple, problem: str, delay: int, left: int) -> str:
    """The warning of a try --retry repeats (post_per_transfer of tool_operate.c): 7.29 says "Transient
    problem", 7.76.1 to 8.5 "Problem :", 8.14 counts in the singular where it is one."""
    if version < (7, 70, 0):
        return qpot_curl_warning(f"Transient problem: {problem} Will retry in {delay} seconds. {left} retries left.")
    if version < (8, 10, 0):
        return qpot_curl_warning(f"Problem : {problem}. Will retry in {delay} seconds. {left} retries left.")
    return qpot_curl_warning(f"Problem : {problem}. Will retry in {delay} second{'' if delay == 1 else 's'}. "
                             f"{left} retr{'y' if left == 1 else 'ies'} left.")


def qpot_curl_http_error(version: tuple, code: int) -> str:
    reason = responses.get(code, "")
    if version < (7, 75, 0) and reason:
        return f"The requested URL returned error: {code} {reason}"
    return f"The requested URL returned error: {code}"


QPOT_CURL_METER_HEAD = ("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                        "                                 Dload  Upload   Total   Spent    Left  Speed\n")


def qpot_curl_max5(count: int) -> str:
    """max5data of curl's progress.c: a byte count in five characters."""
    if count < 100000:
        return f"{count:5d}"
    if count < 10000 * 1024:
        return f"{count // 1024:4d}k"
    if count < 100 * 1048576:
        return f"{count // 1048576:2d}.{count % 1048576 // (1048576 // 10)}M"
    if count < 10000 * 1048576:
        return f"{count // 1048576:4d}M"
    return f"{min(count // 1073741824, 9999):4d}G"


def qpot_curl_meter_line(total: int, received: int, speed: int) -> str:
    """A line of curl's progress meter for a download of total bytes (0: not known) with received of them
    at speed bytes a second."""
    percent = min(received * 100 // total, 100) if total else 0
    m = qpot_curl_max5
    return (f"\r{percent:3d} {m(total)}  {percent:3d} {m(received)}    0 {m(0)}  {m(speed)}  {m(0)} "
            f"--:--:-- --:--:-- --:--:-- {m(speed)}")


def qpot_curl_meter(seconds: int) -> str:
    """A line of curl's progress meter with nothing transferred after so many seconds."""
    spent = "--:--:--" if seconds <= 0 else f"{seconds // 3600}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
    return f"\r  0     0    0     0    0     0      0      0 --:--:-- {spent:>8} --:--:--     0"


class Command_curl(HoneyPotCommand):
    """
    curl command
    """

    _log = Logger()

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    outfile: str | None = None  # outfile is the file saved inside the honeypot
    artifact: (
        Artifact  # artifact is the file saved for forensics in the real file system
    )
    currentlength: int = 0  # partial size during download
    totallength: int = 0  # total length
    silent: bool = False
    head_request: bool = False
    url: bytes
    host: str
    port: int
    # QPot: the parsed command line and the state of the tries
    qpot_opts: dict = {}
    qpot_tries: int = 0
    qpot_timer = None
    qpot_meter: bool = False
    qpot_code: int = 0
    qpot_values: dict = {}
    qpot_bad_outfile: bool = False
    qpot_started: float = 0.0
    qpot_checked: str = ""

    def qpot_version(self) -> tuple:
        from cowrie.commands.coreutils import qpot_os_release

        installed = (getattr(self.protocol, "tpot_installed", None) or {}).get("curl", "")
        found = re.fullmatch(r"([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})", installed)
        if found:
            selected = tuple(int(value) for value in found.groups())
            if selected in QPOT_CURL_BUILDS or selected in ((7, 83, 1), (8, 6, 0)):
                return selected
        os_id, version = qpot_os_release(self.fs)
        return QPOT_CURL_RELEASES.get((os_id, version[0] if version else 0), QPOT_CURL_RECORDED)

    def qpot_show_errors(self) -> bool:
        return not self.silent or bool(self.qpot_opts.get("show-error"))

    @inlineCallbacks
    def start(self):
        # QPot: an installed OpenWrt program still needs its shared libraries.
        if (getattr(self.protocol, "tpot_opkg_added", None) or {}).get("curl"):
            from cowrie.commands.opkg import curl_load_error
            problem = curl_load_error(self.protocol, self.fs)
            if problem:
                self.errorWrite(problem)
                self.exit(127)
                return
        # QPot: curl's parser, not getopt's (see qpot_curl_args)
        version = self.qpot_version()
        try:
            opts, args = qpot_curl_args(self.args, version)
        except QpotCurlUsage as err:
            self.errorWrite(str(err) + QPOT_CURL_TRY)
            self.exit(2)
            return
        self.qpot_opts = opts
        self.qpot_values = {}

        if opts.get("help"):
            self.write(CURL_HELP)
            self.exit()
            return
        if opts.get("version"):
            self.write(self.qpot_version_text(version))
            self.exit()
            return
        self.silent = bool(opts.get("silent"))
        self.head_request = bool(opts.get("head"))

        url = ""
        if len(args) and args[0] is not None:
            url = str(args[0]).strip()
        if not url:
            if self.args:
                text = "curl: (2) no URL specified\n" if version >= (8, 0, 0) else "curl: no URL specified!\n"
                self.errorWrite(text)
            self.errorWrite(QPOT_CURL_TRY)
            self.exit(2)
            return

        if "://" not in url:
            url = "http://" + url

        # urlparse() raises on malformed IPv6 brackets, and .port and .hostname
        # are parsed lazily and raise rather than returning None for a port
        # that is not a decimal 0-65535. The URL is attacker input.
        try:
            urldata = parse.urlparse(url)
            hostname = urldata.hostname
            port = urldata.port
        except ValueError:
            self.qpot_end(3, "URL using bad/illegal format or missing URL")
            return

        if opts.get("output") is not None:
            # `-o -` writes the body to stdout, same as no -o at all.
            self.outfile = opts["output"] if opts["output"] != "-" else None
        if opts.get("remote-name"):
            self.outfile = urldata.path.split("/")[-1]
            if not len(self.outfile.strip()) or not urldata.path.count("/"):
                self.errorWrite("curl: Remote file name has no length!\n")
                self.exit(23)
                return

        if self.outfile:
            self.outfile = self.fs.resolve_path(self.outfile, self.cwd)
            path = posixpath.dirname(self.outfile) if self.outfile else ""
            # QPot: curl opens the file when the first data arrives; a transfer that fails first never
            #   says (see qpot_cannot_write)
            self.qpot_bad_outfile = not path or not self.fs.exists(path) or not self.fs.isdir(path)

        # The URL is attacker input and can contain non-ASCII characters;
        # encoding it as ASCII raised UnicodeEncodeError.
        self.url = url.encode("utf8")

        scheme = urldata.scheme
        if scheme != "http" and scheme != "https":
            self.errorWrite(
                f'curl: (1) Protocol "{scheme}" not supported or disabled in libcurl\n'
            )
            self.exit(1)
            return
        if hostname:
            self.host = hostname
        else:
            self.qpot_end(3, "URL using bad/illegal format or missing URL")
            return
        self.port = port or (443 if scheme == "https" else 80)
        self.qpot_values = {"url": url, "url_effective": url, "scheme": scheme if version >= (7, 85, 0)
                            else scheme.upper(), "method": "HEAD" if self.head_request else "GET"}
        # the meter of a transfer whose output is no terminal (a file, a pipe), unless -s
        self.qpot_meter = not self.silent and (bool(self.outfile) or not self.qpot_to_terminal())

        # QPot: an address the honeypot does not contact is not "unresolved": the machine itself refuses,
        #   the bait's internal hosts and the private networks time out (the persona's network drops them)
        from cowrie.commands.coreutils import qpot_classify, qpot_route

        kind, address = qpot_route(self.fs, self.protocol, self.host)

        # Check rate limit before proceeding
        if kind in ("name", "network") and not curl_rate_limiter.check(self.host):
            self._log.info(
                "curl: rate limit exceeded for host: {host}. Simulating connection timeout",
                host=self.host,
            )
            self.qpot_fail("connect")
            return

        if kind == "name":
            from cowrie.core.network import resolve_cname

            # the one lookup Cowrie made before as well (communication_allowed)
            resolved = yield resolve_cname(self.host, set())
            if self.exited:
                return
            if resolved is None:
                self._log.info("Attempt to access blocked network address")
                self.qpot_fail("unresolved")
                return
            kind, address = qpot_classify(str(resolved)), str(resolved)
        if kind != "network":
            self._log.info("Attempt to access blocked network address")
            self.qpot_values["remote_ip"] = ""
            self.qpot_fail("refused" if kind == "refused" else "connect")
            return
        self.qpot_values.update(remote_ip=address, remote_port=self.port)
        # QPot: the request goes to this address, the one checked (see qpot_fetch)
        self.qpot_checked = address

        self.artifact = Artifact("curl-download")

        # treq.get() can raise synchronously before returning a Deferred (e.g.
        # idna.core.InvalidCodepoint for an IPv4-embedded IPv6 URL literal such
        # as [::ffff:8.8.8.8]). Route that raise through error() so the command
        # exits instead of being orphaned on the cmdstack until session timeout.
        try:
            self.deferred = self.treqDownload(url)
        except Exception:
            self.error(failure.Failure())
            return
        if self.deferred:
            self.deferred.addCallback(self.success)
            self.deferred.addErrback(self.error)

    def qpot_to_terminal(self) -> bool:
        """Whether this command's stdout is the terminal (no pipe, no redirection)."""
        targets = getattr(self.pp, "targets", None) or {}
        target = targets.get(1)
        return target is None or target[0] == "terminal"

    def qpot_version_text(self, version: tuple) -> str:
        if version in ((7, 83, 1), (8, 6, 0)) and (getattr(self.protocol, "tpot_opkg_added", None) or {}).get("curl"):
            from cowrie.commands.opkg import curl_version_text
            text = curl_version_text(self.protocol, version)
            if text is not None:
                return text
        build = QPOT_CURL_BUILDS.get(version, QPOT_CURL_BUILDS[QPOT_CURL_RECORDED])
        if version not in QPOT_CURL_BUILDS:
            version = QPOT_CURL_RECORDED
        number = ".".join(str(x) for x in version)
        from cowrie.commands.uname import hardware_platform

        machine = hardware_platform()
        from cowrie.commands.coreutils import qpot_os_release

        os_id, _ = qpot_os_release(self.fs)
        platform = f"{machine}-redhat-linux-gnu" if os_id in ("rhel", "centos") else f"{machine}-pc-linux-gnu"
        if machine != "x86_64" and os_id not in ("rhel", "centos"):
            platform = f"{machine}-unknown-linux-gnu"
        ssl = re.search(r"OpenSSL ([0-9][0-9a-z.]*)", CowrieConfig.get("shell", "ssh_version", fallback=""))
        libs = build[0] if build[0].startswith("NSS/") else f"OpenSSL/{ssl.group(1) if ssl else '3.0.13'} {build[0]}"
        lines = [f"curl {number} ({platform}) libcurl/{number} {libs}"]
        from cowrie.commands.coreutils import qpot_package_version

        # Debian and Ubuntu build curl with their package's version as its patch stamp
        stamp = qpot_package_version("curl") if os_id in ("debian", "ubuntu") else None
        if build[1]:
            lines.append(f"Release-Date: {build[1]}" + (f", security patched: {stamp}" if stamp else ""))
        lines += [f"Protocols: {build[2]}", f"Features: {build[3]}"]
        return "\n".join(lines) + "\n"

    def qpot_wait(self) -> tuple[float, bool]:
        """(seconds, whether curl's own limit ended it) of a connection that is never answered: -m or
        --connect-timeout where it is shorter than the kernel's SYN retries, else those (curl -m 300 of a
        dropped address fails after 127 s, as the kernel gives up first)."""
        limits = [self.qpot_opts[k] for k in ("max-time", "connect-timeout") if self.qpot_opts.get(k)]
        if limits and min(limits) <= QPOT_KERNEL_TIMEOUT:
            return min(limits), True
        return QPOT_KERNEL_TIMEOUT, False

    def qpot_fail(self, kind: str) -> None:
        """A try that fails without the network: refused and unresolved at once, connect after the
        wait; each try's message, the retries --retry asks for, then the exit status."""
        self.qpot_tries += 1
        if self.qpot_meter and self.qpot_tries == 1:
            self.errorWrite(QPOT_CURL_METER_HEAD)
        if self.qpot_meter:
            self.errorWrite(qpot_curl_meter(0))
        if kind != "connect":
            if self.qpot_meter and kind == "refused":
                self.errorWrite(qpot_curl_meter(0) + "\n")
            self.qpot_failed(kind, 0, random.randint(0, 1))
            return
        wait, _ = self.qpot_wait()
        self.qpot_tick(0, wait)

    def qpot_tick(self, done: int, wait: float) -> None:
        """One second of the wait (the meter's line moves on), then its end."""
        self.qpot_timer = None
        if done and self.qpot_meter:
            self.errorWrite(qpot_curl_meter(done))
        if done + 1 >= wait:
            self.qpot_timer = self.callLater(max(wait - done, 0.0), self.qpot_waited, wait)
            return
        self.qpot_timer = self.callLater(1, self.qpot_tick, done + 1, wait)

    def qpot_waited(self, wait: float) -> None:
        self.qpot_timer = None
        if self.qpot_meter:
            self.errorWrite(qpot_curl_meter(int(wait)) + "\n")
        _, own = self.qpot_wait()
        millis = int(wait * 1000) + random.randint(1, 2) if own else int(wait * 1000) + random.randint(100, 140)
        self.qpot_failed("timeout" if own else "kernel", millis, millis)

    def qpot_failed(self, kind: str, millis: int, spent_ms: int) -> None:
        self.qpot_tries = max(self.qpot_tries, 1)
        version = self.qpot_version()
        code, text = qpot_curl_failure(version, kind, self.host, self.port, millis)
        self.qpot_values.update(http_code="000", response_code="000", exitcode=code, errormsg=text,
                                time_total=f"{spent_ms / 1000:.6f}")
        if self.qpot_show_errors():
            self.errorWrite(f"curl: ({code}) {text}\n")
        transient = kind in ("timeout", "kernel") or (kind == "refused" and (
            self.qpot_opts.get("retry-connrefused") or self.qpot_opts.get("retry-all-errors")))
        if transient and self.qpot_retry("timeout" if kind != "refused" else "connection refused",
                                         lambda: self.qpot_fail("connect" if kind != "refused" else kind)):
            return
        self.qpot_end(code, None)

    def qpot_retry(self, problem: str, again) -> bool:
        """Whether --retry has a try left: its warning (unless -s), then again() after curl's delay
        (--retry-delay, else 1 s doubling up to 10 minutes)."""
        retries = min(int(self.qpot_opts.get("retry") or 0), QPOT_CURL_MAX_RETRIES)
        done = self.qpot_tries - 1
        if done >= retries:
            return False
        fixed = self.qpot_opts.get("retry-delay")
        delay = int(fixed) if fixed else min(1 << min(done, 10), 600)
        if not self.silent:
            self.errorWrite(qpot_curl_retry_warning(self.qpot_version(), problem, delay, retries - done))
        # a delay of 0 still lets the reactor run other sessions between the tries
        self.qpot_timer = self.callLater(max(delay, 0.05), again)
        return True

    def qpot_end(self, code: int, text: str | None) -> None:
        """The end of the transfer: its message (unless -s without -S), --write-out, the exit status."""
        self.qpot_values.setdefault("exitcode", code)
        if text is not None:
            self.qpot_values.setdefault("errormsg", text)
            if self.qpot_show_errors():
                self.errorWrite(f"curl: ({code}) {text}\n")
        self.qpot_write_out()
        self.exit(code)

    def qpot_write_out(self) -> None:
        fmt = self.qpot_opts.get("write-out")
        if not fmt:
            return
        if fmt.startswith("@"):
            fmt = self.qpot_read_format(fmt[1:])
        values = {"http_code": "000", "response_code": "000", "size_download": 0, "size_header": 0,
                  "size_request": 0, "size_upload": 0, "num_redirects": 0, "num_connects": 0, "exitcode": 0,
                  "http_version": "0", "remote_port": -1, "local_port": -1, "speed_download": 0,
                  "speed_upload": 0, "ssl_verify_result": 0, "proxy_ssl_verify_result": 0, "urlnum": 0,
                  "num_headers": 0, "num_retries": max(self.qpot_tries - 1, 0), "time_total": "0.000000"}
        for name in ("time_namelookup", "time_connect", "time_appconnect", "time_pretransfer",
                     "time_starttransfer", "time_redirect"):
            values[name] = "0.000000"
        values.update(self.qpot_values)
        out, err, warnings = qpot_curl_write_out(fmt, values)
        for warning in warnings[:16]:
            self.errorWrite(warning)
        if out:
            self.write(out)
        if err:
            self.errorWrite(err)

    def qpot_read_format(self, name: str) -> str:
        """-w @file: the format read from a file of the tree (@- reads stdin)."""
        if name == "-":
            return (self.input_data or b"")[:QPOT_CURL_WRITE_MAX].decode("utf-8", "replace")
        try:
            path = self.fs.resolve_path(name, self.cwd)
            return self.fs.file_contents(path)[:QPOT_CURL_WRITE_MAX].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - no such file: an empty format
            return ""

    def treqDownload(self, url):
        """
        Download `url`
        """
        headers = {"User-Agent": ["curl/7.38.0"]}

        # curl reports a redirect rather than following it unless -L is given,
        # which cowrie does not implement, so stop at the first response.
        # QPot: -m shortens the wait (never lengthens it); the connection goes to the address start()
        #   checked, never to a second lookup of the name (qpot_fetch)
        from cowrie.commands.coreutils import qpot_fetch

        limit = self.qpot_opts.get("max-time")
        return qpot_fetch(
            url,
            self.qpot_checked,
            method="head" if self.head_request else "get",
            headers=headers,
            timeout=max(1, min(10, int(limit))) if limit else 10,
        )

    def handle_CTRL_C(self) -> None:
        # QPot: ^C during a wait or between tries stops it
        timer = self.qpot_timer
        if timer is not None and timer.active():
            timer.cancel()
        self.qpot_timer = None
        self.write("^C\n")
        self.exit()

    def exit(self, code: int | None = None) -> None:
        # Close the download artifact on every exit path so an aborted download
        # (CTRL-C, a HEAD request, a size limit, ...) does not leave its empty
        # temp file behind in the download directory. close() is idempotent and
        # removes an empty artifact, so the normal success/error paths are
        # unaffected.
        artifact = getattr(self, "artifact", None)
        if artifact is not None:
            artifact.close()
        HoneyPotCommand.exit(self, code)

    def success(self, response):
        """
        successful treq get
        """
        total_length = None if response.length == UNKNOWN_LENGTH else response.length
        self.totallength = total_length or 0
        # QPot: what --write-out and -f need of the response
        code = int(response.code)
        version = getattr(response, "version", (b"HTTP", 1, 1))
        major, minor = int(version[1]), int(version[2])
        types = response.headers.getRawHeaders("content-type") or [b""]
        content_type = types[0].decode(errors="replace") if isinstance(types[0], bytes) else str(types[0])
        self.qpot_values.update(http_code=f"{code:03d}", response_code=f"{code:03d}", content_type=content_type,
                                http_version=f"{major}" if (major, minor) == (1, 0) else f"{major}.{minor}"
                                if minor else f"{major}")
        failed = bool(self.qpot_opts.get("fail")) and code >= 400
        # QPot: curl's meter on stderr, when its output is no terminal or a file (Cowrie wrote one of its own
        #   to stdout, only with -o)
        self.qpot_started = time.monotonic()
        if self.qpot_meter:
            self.errorWrite(QPOT_CURL_METER_HEAD + qpot_curl_meter(0))

        if self.head_request:
            phrase = getattr(response, "phrase", b"") or b""
            reason = (phrase.decode(errors="replace") if isinstance(phrase, bytes) else str(phrase)) or \
                responses.get(response.code, "")
            # QPot: the status line and headers as the server sent them, each ending in CRLF, and the
            #   blank line after them
            self.write(f"HTTP/{major}.{minor} {response.code} {reason}\r\n")
            # Header bytes come from an attacker-directed server and need
            # not be valid UTF-8.
            for key, values in response.headers.getAllRawHeaders():
                decoded_key = (
                    key.decode(errors="replace") if isinstance(key, bytes) else key
                )
                for value in values:
                    decoded_value = (
                        value.decode(errors="replace")
                        if isinstance(value, bytes)
                        else value
                    )
                    # QPot: the empty Content-Encoding the HTTP client adds is not the server's
                    if decoded_key.lower() == "content-encoding" and not decoded_value.strip():
                        continue
                    self.write(f"{decoded_key}: {decoded_value}\r\n")
            self.write("\r\n")
            if self.qpot_meter:
                self.errorWrite(qpot_curl_meter_line(0 if failed else self.totallength, 0, 0) + "\n")
            if failed:
                self.qpot_http_failed(code)
                return
            self.qpot_end(0, None)
            return

        if failed:
            # QPot: -f: no body, curl's error 22 (a transient code is tried again as --retry asks,
            #   without fetching it again)
            abort_body(response)
            if self.qpot_meter:
                self.errorWrite(qpot_curl_meter(0) + "\n")
            self.qpot_http_failed(code)
            return

        if self.outfile and self.qpot_bad_outfile:
            self.qpot_cannot_write(response, total_length)
            return

        if (
            total_length is not None
            and self.limit_size > 0
            and self.totallength > self.limit_size
        ):
            self._log.info(
                "Not saving URL ({url}) (size: {size}) exceeds file size limit ({limit})",
                url=self.url.decode(),
                size=self.totallength,
                limit=self.limit_size,
            )
            self.exit()
            # Stop the transfer; an undelivered body would otherwise keep
            # downloading and buffering in memory.
            abort_body(response)
            return

        deferred = treq.collect(response, self.collect)
        deferred.addCallback(self.collectioncomplete)
        return deferred

    def qpot_cannot_write(self, response, total_length) -> None:
        """-o into a folder that is not there: curl's warning when the first data arrives, then 23."""
        abort_body(response)
        size = min(total_length, 16384) if total_length else 16384
        if self.qpot_version() >= (8, 0, 0):
            warning, text = "open", f"client returned ERROR on write of {size} bytes"
        else:
            warning, text = "create", f"Failed writing body (0 != {size})"
        if not self.silent:
            self.errorWrite(f"Warning: Failed to {warning} the file {self.outfile}: No such file or directory\n")
        if self.qpot_meter:
            self.errorWrite(qpot_curl_meter_line(total_length or 0, 0, 0) + "\n")
        self.qpot_end(23, text)

    def qpot_http_failed(self, code: int) -> None:
        self.qpot_tries += 1
        text = qpot_curl_http_error(self.qpot_version(), code)
        self.qpot_values.update(exitcode=22, errormsg=text)
        if self.qpot_show_errors():
            self.errorWrite(f"curl: (22) {text}\n")
        if code in QPOT_CURL_TRANSIENT and self.qpot_retry("HTTP error", lambda: self.qpot_http_failed(code)):
            return
        self.qpot_values["errormsg"] = text
        self.qpot_write_out()
        self.exit(22)

    def collect(self, data: bytes) -> None:
        """
        partial collect
        """
        if self.exited:
            # The command exited while the transfer was still in flight (size
            # limit, CTRL-C); drop late chunks instead of writing to the
            # closed artifact.
            return
        self.currentlength += len(data)
        if self.limit_size > 0 and self.currentlength > self.limit_size:
            self._log.info(
                "Not saving URL ({url}) (size: {size}) exceeds file size limit ({limit})",
                url=self.url.decode(),
                size=self.currentlength,
                limit=self.limit_size,
            )
            self.exit()
            # treq closes the connection when the collector raises, aborting
            # the transfer instead of draining the rest of the body. The
            # errback this triggers is inert because the command has exited.
            raise DownloadLimitExceeded

        self.artifact.write(data)

        if not self.outfile:
            self.writeBytes(data)

    def collectioncomplete(self, data: None) -> None:
        """
        this gets called once collection is complete
        """
        if self.exited:
            # The command exited while the transfer was still in flight; the
            # partial artifact was already handled by exit(), so don't report
            # a download for a dead command or exit again.
            return
        self.artifact.close()

        if self.qpot_meter:
            spent = max(time.monotonic() - self.qpot_started, 0.001)
            size = self.currentlength
            self.errorWrite(qpot_curl_meter_line(self.totallength or size, size, int(size / spent)) + "\n")

        capture_download(
            self,
            self.artifact,
            self.url.decode(),
            outfile=self.outfile,
            size=self.currentlength,
        )
        # QPot: --write-out after the body
        self.qpot_values["size_download"] = self.currentlength
        self.qpot_write_out()
        self.exit()

    def error(self, response):
        """
        handle any exceptions
        """
        if self.exited:
            # The command exited while the transfer was still in flight; a
            # late failure of that transfer is not this command's outcome.
            return
        self.exit_code = 1
        report_download_failure(self, self.url.decode())

        # QPot: the failures as the release's curl words them, with their exit status
        if response.check(BlockedAddress) is not None:
            self.qpot_failed("unresolved", 0, 0)
            return

        if response.check(UnreachableAddress) is not None:
            self.qpot_failed("refused", 0, 0)
            return

        if response.check(error.DNSLookupError) is not None:
            self.qpot_failed("unresolved", 0, 0)
            return

        elif response.check(error.ConnectingCancelledError) is not None:
            limit = self.qpot_opts.get("max-time")
            wait = max(1, min(10, int(limit))) if limit else 10
            self.qpot_failed("timeout", wait * 1000 + 1, wait * 1000 + 1)
            return

        elif response.check(error.ConnectionRefusedError) is not None:
            self.qpot_failed("refused", 0, 0)
            return

        elif response.check(error.TCPTimedOutError) is not None:
            self.qpot_failed("kernel", QPOT_KERNEL_TIMEOUT * 1000 + 120, QPOT_KERNEL_TIMEOUT * 1000 + 120)
            return

        # possible errors:
        # defer.CancelledError,
        # error.ConnectingCancelledError,

        self._log.failure("Unhandled curl error", failure=response)
        self.write("\n")

        self.exit()


commands["/usr/bin/curl"] = Command_curl
commands["curl"] = Command_curl
