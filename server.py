import os, base64, urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs

BLOCK = set("""
doubleclick.net googlesyndication.com googleadservices.com
adnxs.com adsrvr.org criteo.com criteo.net
taboola.com outbrain.com pubmatic.com
rubiconproject.com openx.net smartadserver.com
scorecardresearch.com quantserve.com moatads.com
appsflyer.com adjust.com
""".split())

UPSTREAM = "https://cloudflare-dns.com/dns-query"

def question(packet):
    if len(packet) < 17 or packet[4:6] != b"\x00\x01":
        raise ValueError("Invalid query")
    pos, parts = 12, []
    while True:
        if pos >= len(packet):
            raise ValueError("Invalid name")
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(packet):
            raise ValueError("Invalid label")
        parts.append(packet[pos:pos + size].decode("ascii").lower())
        pos += size
    if pos + 4 > len(packet):
        raise ValueError("Invalid question")
    return ".".join(parts), pos + 4

def blocked(name):
    return any(name == x or name.endswith("." + x) for x in BLOCK)

def resolve(packet):
    name, end = question(packet)
    if blocked(name):
        return (packet[:2] + b"\x81\x83" +
                b"\x00\x01" + b"\x00\x00" * 3 +
                packet[12:end])
    req = urllib.request.Request(
        UPSTREAM, data=packet,
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"},
        method="POST")
    with urllib.request.urlopen(req, timeout=8) as response:
        result = response.read(65535)
    if result[:2] != packet[:2]:
        raise ValueError("Invalid upstream response")
    return result

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, data, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def process(self, packet):
        try:
            if not 12 <= len(packet) <= 4096:
                raise ValueError("Invalid size")
            result = resolve(packet)
            self.reply(200, result, "application/dns-message")
        except ValueError:
            self.reply(400, b"Invalid DNS query")
        except Exception:
            self.reply(502, b"DNS upstream failed")

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/healthz":
            return self.reply(200, b"OK")
        if url.path != "/dns-query":
            return self.reply(404, b"Not found")
        try:
            value = parse_qs(url.query)["dns"][0]
            packet = base64.urlsafe_b64decode(value + "===")
            self.process(packet)
        except Exception:
            self.reply(400, b"Invalid DNS parameter")

    def do_POST(self):
        if urlsplit(self.path).path != "/dns-query":
            return self.reply(404, b"Not found")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/dns-message":
            return self.reply(415, b"Invalid content type")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.reply(400, b"Invalid length")
        if not 12 <= length <= 4096:
            return self.reply(413, b"Invalid size")
        self.process(self.rfile.read(length))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
