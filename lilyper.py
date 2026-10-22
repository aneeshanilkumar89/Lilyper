#!/usr/bin/env python3
"""
Lilyper (formerly LLMap) - sqlmap-style LLM/agent injection tester.

Concept mapping:
  - sqlmap -r FILE        -> load a raw HTTP request template (-r)
  - wfuzz FUZZ marker     -> mark injection position(s) in the request body
  - pyrit scorers         -> deterministic signature-based response analysis
                             (NO LLM used for detection)
  - own methodology       -> proxy routing, SSE parsing, N-run confirmation,
                             Burp search strings per finding

Usage:
  python3 lilyper.py -r request.txt --proxy http://192.168.222.1:8080
  python3 lilyper.py -r request.txt --categories llm01,llm07,ag01 --confirm 2
  python3 lilyper.py --list
  python3 lilyper.py -r request.txt --dry-run
"""
import sys, os, argparse, json, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.request import ParsedRequest, parse_request_file, MarkerMissingError
from core.engine import Engine
from core import PAYLOADS_DIR

BANNER = r"""
\x1b[36m
 _     _ _
| |   (_) |_   _ _ __   ___ _ __
| |   | | | | | | '_ \ / _ \ '__|
| |___| | | |_| | |_) |  __/ |
|_____|_|_|\__, | .__/ \___|_|
           |___/|_|\x1b[0m
\x1b[1;37m  sqlmap-style LLM/Agent injection tester\x1b[0m
\x1b[2m  FUZZ-marker payloads | OWASP LLM Top 10 + Agentic AI categories
  deterministic signature detection (no LLM judging)\x1b[0m
"""

USAGE = """
\x1b[1mQUICK START\x1b[0m

  \x1b[32m# list payload categories\x1b[0m
  python3 lilyper.py --list

  \x1b[32m# full run against a captured request, through Burp\x1b[0m
  python3 lilyper.py -r request.txt --proxy http://192.168.222.1:8080

  \x1b[32m# targeted categories, aggressive level, confirmation runs\x1b[0m
  python3 lilyper.py -r request.txt --proxy http://192.168.222.1:8080 \\
      --categories llm01,llm07,ag01 --level 3 --confirm 2

  \x1b[32m# preview injections without sending anything\x1b[0m
  python3 lilyper.py -r request.txt --dry-run

  \x1b[32m# add your own payload list\x1b[0m
  python3 lilyper.py -r request.txt --extra-payloads mypayloads.txt

\x1b[1mREQUEST FILE\x1b[0m
  Raw HTTP request (Burp "copy to file"). Put \x1b[1mFUZZ\x1b[0m where the payload
  goes, e.g.  {"message":"FUZZ", ...}   - see examples/example_request.txt
  Full help:  python3 lilyper.py -h
"""


def print_banner():
    print(BANNER.replace("\\x1b", "\x1b"))


def build_parser():
    p = argparse.ArgumentParser(prog="Lilyper", description="LLM/Agent injection tester (sqlmap-style) - formerly LLMap")
    p.add_argument("-r", "--request", help="raw HTTP request file with FUZZ marker")
    p.add_argument("--proxy", default=None, help="proxy URL, e.g. http://192.168.222.1:8080")
    p.add_argument("--marker", default="FUZZ", help="injection placeholder (default: FUZZ)")
    p.add_argument("--categories", default="all", help="comma list: llm01,llm07,ag01 or 'all'")
    p.add_argument("--level", type=int, default=2, choices=[1, 2, 3],
                   help="1=recon only, 2=standard battery (default), 3=aggressive")
    p.add_argument("--confirm", type=int, default=2,
                   help="reruns for MEDIUM+ detections to measure reliability (default 2 -> N/N+1)")
    p.add_argument("--timeout", type=int, default=240)
    p.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
    p.add_argument("--extra-payloads", dest="extra", default=None,
                   help="extra payload file (one payload per line)")
    p.add_argument("--baseline", default="Hello! Quick test - reply with one short sentence.")
    p.add_argument("--canary", action="store_true",
                   help="append unique audit-ref token per payload; flag if echoed back")
    p.add_argument("--output-dir", default=None, help="output dir (default: lilyper_output/<ts>)")
    p.add_argument("--no-insecure", action="store_true", help="verify TLS certs (default: off)")
    p.add_argument("--dry-run", action="store_true", help="print injections, send nothing")
    p.add_argument("--list", action="store_true", help="list payload categories and exit")
    return p


def main():
    # banner: no options, --help, -h, or --list
    bare = len(sys.argv) == 1
    wants_help = ("--help" in sys.argv) or ("-h" in sys.argv)
    wants_list = ("--list" in sys.argv)
    if bare or wants_help or wants_list:
        print_banner()
    if bare:
        print(USAGE.replace("\\x1b", "\x1b"))
        return 0

    args = build_parser().parse_args()

    if not args.request:
        print("Payload categories (%s):" % PAYLOADS_DIR)
        for f in sorted(os.listdir(PAYLOADS_DIR)):
            if f.endswith(".txt"):
                n = sum(1 for l in open(os.path.join(PAYLOADS_DIR, f))
                        if l.strip() and not l.startswith("#"))
                print("  %-32s %3d payloads" % (f[:-4], n))
        if not args.request:
            print("\nNo -r given. Use: lilyper.py -r request.txt [--proxy ...]")
        return 0

    try:
        req = parse_request_file(args.request)
    except MarkerMissingError:
        print("[!] No %s marker found in request body. Add it where the payload goes." % args.marker)
        return 1

    print("[*] Target   : %s %s" % (req.method, req.url))
    print("[*] Marker   : %s (%d occurrence(s) in body)" % (args.marker, req.body.count(args.marker)))
    print("[*] Body len : %d | JSON context: %s" % (len(req.body), req.json_context))
    print("[*] Proxy    : %s | TLS verify: %s" % (args.proxy or "direct", not args.no_insecure))

    eng = Engine(req, args)
    findings = eng.run()

    print("\n[+] %d finding(s). Report: %s" % (len(findings), eng.report_path))
    for f in findings:
        print("  [%s] %s  (%s)  burp-search: %r" %
              (f["severity"], f["category"], f["reliability"], f["burp_search"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
