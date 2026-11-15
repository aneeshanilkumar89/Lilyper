# Lilyper

sqlmap-style LLM/agent security tester. Load a raw HTTP request (sqlmap `-r`
concept), mark the injection position with `FUZZ` (wfuzz concept), fire a
payload library organized by OWASP LLM Top 10 + Agentic AI categories, and
detect hits with deterministic regex signatures (pyrit-scorer concept) -
**no LLM is used for detection**.

## How it maps

| Concept | Source | LLMap implementation |
|---|---|---|
| `-r request.txt` raw request template | sqlmap | `core/request.py` parses Burp "copy to file" requests (origin-form or absolute), recomputes body |
| `FUZZ` position marker | wfuzz | every occurrence of the marker in the request body is replaced by the current payload |
| grep-based boolean/error detection | sqlmap | `core/analyzer.py` - credential regexes, sysleak markers, identity+confidentiality co-occurrence, refusal classification, baseline length-diff |
| scorers / targets / orchestrator | pyrit | categories = attack strategies; analyzer = scorer; engine = orchestrator with N-run confirmation |
| evidence methodology | field runs | every request/response saved; findings include Burp search strings; confirmation runs report N/N+1 reliability |

## Usage

    # list payload categories
    python3 lilyper.py --list

    # full run against a captured request, through Burp
    python3 lilyper.py -r request.txt --proxy http://192.168.222.1:8080

    # targeted categories with confirmation runs
    python3 lilyper.py -r request.txt --proxy http://192.168.222.1:8080 \
        --categories llm01,llm07,ag01 --confirm 2 --level 3

    # show injections without sending (template debugging)
    python3 lilyper.py -r request.txt --dry-run

    # custom payload list appended
    python3 lilyper.py -r request.txt --extra-payloads mypayloads.txt

    # optional LLM second pass over refusals/near-misses (separate output)
    python3 lilyper.py -r request.txt --judge \
        --judge-url http://localhost:11434/v1 --judge-model llama3.1

## Request file

Raw HTTP exactly as captured (headers + blank line + body). Put `FUZZ` where
the payload goes:

    {"message":"FUZZ","history":[], ...}

JSON bodies: payloads are stored **pre-escaped** (`\n`, `\"`, `\\` stay as
two-character escapes) exactly like `payloads.txt` from the field runs, so
the server-side JSON decode yields the real text. Non-JSON bodies: escapes
are decoded to real characters automatically.

## Payload levels & categories

- Level 1 = recon, 2 = standard battery (default), 3 = aggressive
  (override framing, regex-priming, action attempts). `--level 3` to enable.
- Files in `payloads/` (212 payloads across 24 categories):
  - `llm01`..`llm10` - OWASP LLM Top 10 2025.
  - `ag01`..`ag10` - OWASP Top 10 for Agentic Applications (identity spoofing,
    trust boundaries, context/memory, onward injection, unbounded agency, tool
    abuse, goal hijacking, code execution, supply chain, cascading/rogue).
  - `evd01`..`evd03`, `ind01` - technique layer: obfuscation/encoding, policy
    puppetry, multi-turn/many-shot seeds, indirect/stored injection. Evasion
    probes use a benign `LILYCANARY` sentinel so a hit is unambiguous.
- Format: one payload per line, `#` comments, optional `1|`/`3|` level prefix.

## Detection (no LLM)

| Signature class | Severity |
|---|---|
| credential patterns (sk-, AIza, AKIA, ghp_, xox, JWT, PEM, secret=) | CRITICAL |
| sysleak markers (`<instr>`, BEGIN SYSTEM..., "system prompt:") | CRITICAL |
| "You are ..." + "must not/never reveal..." co-occurrence | CRITICAL |
| guardrail terminology (guardrail, raw data block, tier refs) | HIGH |
| injected-data echo (`"scope":`, `by_status`, live data) | HIGH |
| model fingerprint mentions | INFO |
| rate/quota signals (429, quota exceeded) | INFO |
| baseline length-diff >= 1.6x non-refusal | INFO |

MEDIUM+ findings trigger automatic confirmation reruns (`--confirm`, default
2 -> reliability reported as N/N+1).

## AI-assisted review (optional)

`--judge` adds an opt-in LLM second pass over responses the regex did not flag
(refusals and near-misses), to catch semantic leaks that match no fixed
signature. It talks to any OpenAI-compatible endpoint (`--judge-url`,
`--judge-model`, key via the `LILYPER_JUDGE_KEY` env var), so it works with a
local model (Ollama, LM Studio) or a hosted one. Verdicts are written to
`judge.json` and `judge_report.md` only, and are never mixed into the
deterministic `findings.json` / `report.md`. Off by default: a run without
`--judge` is byte-for-byte the deterministic result.

## Output

    lilyper_output/<timestamp>/
      report.md          findings + Burp search strings + full request table
      findings.json      machine-readable findings
      evidence/          0001_req.txt / 0001_resp.txt per request (screenshot source)
      judge_report.md    (only with --judge) AI-assisted review, manual confirm
      judge.json         (only with --judge) machine-readable judge verdicts

## Notes / limits

- Sequential requests with `--delay` (default 1s); keep total call counts low.
- Auth tokens in the request file are live credentials - redact before
  sharing output. Tokens may rotate mid-run: if 401 storms appear, recapture.
- Multi-turn poisoning (history[] injection) needs the history field edited
  in the request template per attempt (see ag03 payloads).
- Indirect-injection (`ind01`) payloads are meant to be planted in content the
  agent ingests (a document, field, or tool output), not sent as the user turn.
