#!/usr/bin/env python3
"""Passively audit authorized HTTP response headers."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def parse_headers(text):
    headers, status_code = {}, None
    for line in text.splitlines():
        status = re.match(r"^HTTP/\S+\s+(\d{3})", line, re.I)
        if status:
            status_code = int(status.group(1))
        match = re.match(r"^([^:]+):\s*(.*)$", line)
        if match:
            headers.setdefault(match.group(1).strip().lower(), []).append(match.group(2).strip())
    return headers, status_code


def first(headers, name):
    return headers.get(name, [""])[0]


def audit(text, target):
    headers, status_code = parse_headers(text)
    hsts, csp = first(headers, "strict-transport-security"), first(headers, "content-security-policy")
    xcto, xfo = first(headers, "x-content-type-options").lower(), first(headers, "x-frame-options").lower()
    referrer, permissions, cookies = first(headers, "referrer-policy").lower(), first(headers, "permissions-policy"), headers.get("set-cookie", [])
    server = first(headers, "server") or first(headers, "x-powered-by")
    checks = []

    def add(identifier, title, state, detail, fix):
        checks.append({"id": identifier, "title": title, "state": state, "detail": detail, "fix": fix})

    if not hsts: add("hsts", "Strict-Transport-Security", "fail", "HSTS is missing, so the browser may accept a downgraded connection.", "Send max-age=31536000; includeSubDomains over HTTPS.")
    elif not re.search(r"max-age\s*=\s*(\d{8,})", hsts, re.I): add("hsts", "Strict-Transport-Security", "warn", "HSTS is present but its max-age is shorter than the baseline.", "Use a max-age of at least 31536000 seconds.")
    else: add("hsts", "Strict-Transport-Security", "pass", "Long-lived HSTS is enabled.", "")
    if not csp: add("csp", "Content-Security-Policy", "fail", "No content policy was observed, leaving sources unrestricted.", "Define a least-privilege policy such as default-src 'self'.")
    elif re.search(r"unsafe-inline|unsafe-eval|(^|\s)\*(\s|;|$)", csp, re.I): add("csp", "Content-Security-Policy", "warn", "A policy exists but contains a broad or unsafe source expression.", "Remove unsafe-inline, unsafe-eval, and wildcard sources where possible.")
    else: add("csp", "Content-Security-Policy", "pass", "A focused content policy is present.", "")
    add("mime", "X-Content-Type-Options", "pass" if xcto == "nosniff" else "fail", "MIME sniffing is disabled." if xcto == "nosniff" else "The browser can guess content types instead of honoring the declared type.", "" if xcto == "nosniff" else "Send X-Content-Type-Options: nosniff.")
    frame_pass = xfo in {"deny", "sameorigin"} or bool(re.search(r"frame-ancestors\s+(?!\*)", csp, re.I))
    add("frame", "Frame protection", "pass" if frame_pass else "fail", "Framing is restricted by X-Frame-Options or CSP frame-ancestors." if frame_pass else "No reliable clickjacking boundary was observed.", "" if frame_pass else "Send X-Frame-Options: DENY or define CSP frame-ancestors.")
    safe_referrer = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    add("referrer", "Referrer-Policy", "pass" if referrer in safe_referrer else "warn", "Cross-origin referrer detail is constrained." if referrer in safe_referrer else "The browser may send more URL context than intended.", "" if referrer in safe_referrer else "Use strict-origin-when-cross-origin or a stricter policy.")
    add("permissions", "Permissions-Policy", "pass" if permissions else "warn", "Powerful browser features have an explicit policy." if permissions else "No Permissions-Policy was observed.", "" if permissions else "Declare the features your app does not need.")
    if not cookies: add("cookies", "Session cookie flags", "warn", "No Set-Cookie header was observed; review this path if the app uses sessions.", "Session cookies should use Secure, HttpOnly, and SameSite.")
    else:
        missing = []
        if any(not re.search(r";\s*secure(?:;|$)", cookie, re.I) for cookie in cookies): missing.append("Secure")
        if any(not re.search(r";\s*httponly(?:;|$)", cookie, re.I) for cookie in cookies): missing.append("HttpOnly")
        if any(not re.search(r";\s*samesite=", cookie, re.I) for cookie in cookies): missing.append("SameSite")
        add("cookies", "Session cookie flags", "warn" if missing else "pass", f"Some cookies are missing: {', '.join(missing)}." if missing else "Observed cookies carry Secure, HttpOnly, and SameSite attributes.", "Add the missing attributes to session cookies." if missing else "")
    add("disclosure", "Server disclosure", "warn" if server else "pass", "A Server or X-Powered-By value reveals implementation detail." if server else "No obvious implementation disclosure header was observed.", "Remove or minimize identifying response headers." if server else "")
    counts = {state: sum(check["state"] == state for check in checks) for state in ("pass", "warn", "fail")}
    score = round(sum(1 if check["state"] == "pass" else .5 if check["state"] == "warn" else 0 for check in checks) / len(checks) * 100)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "target": target or "pasted-response", "status_code": status_code, "summary": {"score": score, **counts, "controls": len(checks)}, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="authorized file containing response headers")
    parser.add_argument("--target", default="", help="label for the response")
    parser.add_argument("--output", type=Path, help="write JSON report to this path")
    args = parser.parse_args()
    if not args.input.is_file(): parser.error(f"input file does not exist: {args.input}")
    report = audit(args.input.read_text(encoding="utf-8", errors="replace"), args.target)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(rendered, encoding="utf-8"); print(f"Report written to {args.output}")
    else: print(rendered, end="")


if __name__ == "__main__": main()
