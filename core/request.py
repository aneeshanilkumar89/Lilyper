"""Raw request parsing, FUZZ injection, and sending (sqlmap -r concept)."""
import json
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MarkerMissingError(Exception):
    pass


class ParsedRequest(object):
    def __init__(self, method, url, host, path, headers, body):
        self.method = method
        self.url = url
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
        self.json_context = False
        try:
            json.loads(body)
            self.json_context = True
        except Exception:
            pass
        self._session = requests.Session()

    def count_marker(self, marker):
        return self.body.count(marker)

    def inject(self, payload, marker="FUZZ"):
        """Replace every marker occurrence with the payload.

        JSON-string context (payloads stored pre-escaped with \\n, \\", \\\\):
        injected verbatim so server-side JSON decoding yields the real text.
        Non-JSON context: escape sequences are decoded to real characters.
        """
        if not self.json_context:
            payload = payload.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        return self.body.replace(marker, payload)

    def send(self, body, proxy=None, insecure=True, timeout=240):
        """Send request with an injected body. Returns (status, ctype, full_text).

        SSE responses (text/event-stream) are flattened: data: {"token": "..."}
        chunks are concatenated, so analysis greps the final rendered reply.
        """
        proxies = {"http": proxy, "https": proxy} if proxy else None
        r = self._session.request(
            self.method, self.url,
            headers=dict(self.headers),
            data=body.encode("utf-8", "replace"),
            proxies=proxies, verify=(not insecure), timeout=timeout,
            allow_redirects=False,
        )
        ctype = r.headers.get("content-type", "")
        text = r.text
        if "text/event-stream" in ctype:
            text = _flatten_sse(r.text)
        return r.status_code, ctype, text, r.headers


def _flatten_sse(raw):
    out = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        d = line[5:].strip()
        if d == "[DONE]":
            continue
        try:
            j = json.loads(d)
            if isinstance(j, dict):
                for k in ("token", "delta", "content", "answer", "text", "chunk", "v", "message"):
                    v = j.get(k)
                    if isinstance(v, str):
                        out.append(v)
                        break
            elif isinstance(j, str):
                out.append(j)
        except Exception:
            out.append(d)
    return "".join(out)


def parse_request_file(path, marker="FUZZ"):
    """Parse a raw HTTP request file (Burp 'copy to file' format)."""
    raw = open(path, "r", encoding="utf-8", errors="replace").read()
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    method, target, _proto = lines[0].split(" ", 2)

    headers = {}
    host = ""
    for h in lines[1:]:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()

    if target.lower().startswith("http"):
        url = target
    else:
        url = "https://%s%s" % (host, target)

    # drop hop-by-hop / length headers we must recompute
    for drop in ("Content-Length", "content-length", "Connection", "connection", "TE", "te"):
        headers.pop(drop, None)

    req = ParsedRequest(method, url, host, target, headers, body)
    if marker not in body:
        raise MarkerMissingError("marker %s not in body" % marker)
    return req
