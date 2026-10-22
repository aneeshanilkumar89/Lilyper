"""Orchestration engine: payload loading, injection loop, confirmation runs,
evidence logging and report generation (Burp search strings included)."""
import os
import re
import json
import time
import random

from .analyzer import analyze, is_refusal
from . import PAYLOADS_DIR

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_payloads(categories, level):
    """Return [(category, payload, level), ...] from payloads/*.txt.

    Payload file format: one payload per line; '#' comments; optional
    level prefix '1|' or '3|' (default level 2).
    """
    out = []
    files = sorted(f for f in os.listdir(PAYLOADS_DIR) if f.endswith(".txt"))
    if categories and categories != "all":
        wanted = set(c.strip().lower() for c in categories.split(","))
    else:
        wanted = None
    for f in files:
        cat = f[:-4].split("_")[0].lower()          # llm01, ag01, custom...
        code = f[:-4].lower()
        if wanted and cat not in wanted and code not in wanted:
            continue
        for line in open(os.path.join(PAYLOADS_DIR, f), encoding="utf-8"):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            if line[:2] in ("1|", "3|"):
                lvl = int(line[0])
                line = line[2:]
            else:
                lvl = 2
            if lvl > level:
                continue
            out.append((code, line, lvl))
    return out


class Engine(object):
    def __init__(self, req, args):
        self.req = req
        self.args = args
        self.marker = args.marker
        ts = time.strftime("%Y%m%d-%H%M%S")
        self.outdir = args.output_dir or os.path.join("lilyper_output", ts)
        self.eviddir = os.path.join(self.outdir, "evidence")
        os.makedirs(self.eviddir, exist_ok=True)
        self.report_path = os.path.join(self.outdir, "report.md")
        self.results = []
        self.n = 0

    def _send(self, payload, label=""):
        body = self.req.inject(payload, self.marker)
        if self.args.canary:
            body = body.replace(self.marker, "")  # no-op; canary appended below
        status, ctype, text, hdrs = self.req.send(
            body, proxy=self.args.proxy,
            insecure=(not self.args.no_insecure),
            timeout=self.args.timeout)
        self.n += 1
        tag = "%04d" % self.n
        with open(os.path.join(self.eviddir, tag + "_req.txt"), "w") as fh:
            fh.write("%s %s\n\n%s" % (self.req.method, self.req.path, body))
        with open(os.path.join(self.eviddir, tag + "_resp.txt"), "w") as fh:
            fh.write("HTTP %s %s\n\n%s" % (status, ctype, text))
        return status, text

    def _send_canary(self, payload):
        """Send payload with a unique audit-ref; return (status, text, canary)."""
        canary = None
        if self.args.canary:
            canary = "ZQAUDIT%s" % "".join(random.choice("0123456789abcdef") for _ in range(6))
            payload = payload + " [audit-ref:%s]" % canary
        status, text = self._send(payload)
        return status, text, canary

    def run(self):
        args = self.args
        payloads = load_payloads(args.categories, args.level)
        if args.extra and os.path.exists(args.extra):
            for line in open(args.extra, encoding="utf-8"):
                if line.strip() and not line.startswith("#"):
                    payloads.append(("custom", line.rstrip("\n"), 2))

        if args.dry_run:
            print("[*] Loaded %d payloads (categories=%s level=%d)" %
                  (len(payloads), args.categories, args.level))
            for cat, p, lvl in payloads:
                print("  [dry] %-28s L%d: %s" % (cat, lvl, p[:110]))
            print("[dry-run] %d payloads total; no requests sent." % len(payloads))
            self._report([])
            return []

        print("[*] Loaded %d payloads (categories=%s level=%d)" %
              (len(payloads), args.categories, args.level))
        print("[*] Baseline request...")
        baseline = {"len": 0, "refusal": False}
        try:
            b_status, b_text = self._send(args.baseline)
            baseline = {"len": len(b_text), "refusal": is_refusal(b_text)}
            print("[*] Baseline: len=%d refusal=%s" % (baseline["len"], baseline["refusal"]))
        except Exception as e:
            print("[!] Baseline failed (%s) - continuing without baseline diff." % str(e)[:120])

        interesting = []
        for cat, payload, lvl in payloads:
            try:
                status, text, canary = self._send_canary(payload)
            except Exception as e:
                print("  [ERR] %-28s L%d send failed: %s" % (cat, lvl, str(e)[:120]))
                continue
            dets = analyze(text, status=status, baseline=baseline, canary=canary)
            refusal = is_refusal(text)
            hit = [d for d in dets if d["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
            flag = "HIT " if hit else ("ref " if refusal else "    ")
            print("  [%s] %-28s L%d len=%-5d %s" %
                  (flag, cat, lvl, len(text), "; ".join(d["name"] for d in hit) or
                   ("refusal" if refusal else "-")))
            self.results.append({"category": cat, "payload": payload, "level": lvl,
                                 "status": status, "len": len(text),
                                 "refusal": refusal, "detections": dets,
                                 "text": text})
            if hit:
                interesting.append((cat, payload, lvl, hit, text))
            if args.delay:
                time.sleep(args.delay)

        # confirmation runs for MEDIUM+ detections (N/N+1 reliability)
        findings = []
        for cat, payload, lvl, hit, text in interesting:
            succ = 1
            for _ in range(args.confirm):
                s2, t2 = self._send(payload)
                d2 = [d for d in analyze(t2, status=s2) if d["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
                if d2:
                    succ += 1
                time.sleep(args.delay)
            for d in hit:
                d2 = dict(d)
                d2.update({"category": cat, "payload": payload,
                           "reliability": "%d/%d" % (succ, args.confirm + 1),
                           "burp_search": self._burp_search(payload)})
                findings.append(d2)

        findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"]))
        self._report(findings)
        return findings

    @staticmethod
    def _burp_search(payload):
        """Distinctive substring of the payload for Burp history screenshot search."""
        m = re.search(r"[A-Za-z0-9_\[\{][A-Za-z0-9_ \[\]{}.:,'\"()-]{15,60}", payload)
        return (m.group(0).strip() if m else payload[:40])

    def _report(self, findings):
        with open(self.report_path, "w") as fh:
            fh.write("# Lilyper Report\n\n*Target:* %s %s\n*Requests:* %d  \n*Generated:* %s\n\n" %
                     (self.req.method, self.req.url, self.n, time.strftime("%Y-%m-%d %H:%M:%S")))
            fh.write("## Findings\n\n")
            if not findings:
                fh.write("No MEDIUM+ signature detections.\n\n")
            for f in findings:
                fh.write("### [%s] %s - %s (reliability %s)\n\n" %
                         (f["severity"], f["name"], f["category"], f.get("reliability", "?")))
                fh.write("* Payload: `%s`\n" % f["payload"][:300])
                fh.write("* Evidence: `%s`\n" % f["evidence"])
                fh.write("* Burp search: `%s`\n\n" % f.get("burp_search", ""))
            fh.write("## All requests\n\n| # | category | refusal | len | detections |\n|--|--|--|--|--|\n")
            for i, r in enumerate(self.results, 1):
                fh.write("| %d | %s | %s | %d | %s |\n" %
                         (i, r["category"], r["refusal"], r["len"],
                          ", ".join(d["name"] for d in r["detections"]) or "-"))
        with open(os.path.join(self.outdir, "findings.json"), "w") as fh:
            json.dump(findings, fh, indent=2)
