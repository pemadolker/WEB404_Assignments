"""
app.py
Aperture, a small community photo gallery. People upload a picture and it
shows up in the gallery for everyone to see.

The gallery is also the lab. The upload feature exists in two modes:

  Vulnerable mode  ->  POST /upload
  Secure mode      ->  POST /secure/upload

The mode switch in the top right just changes which of those the form posts to.
Everything else about the page is identical, so the only thing that changes
between a safe upload and an unsafe one is the handler that receives the file.

What the vulnerable handler does wrong:
  - trusts the filename the browser sent (so ../ escapes the folder)
  - trusts the extension and the Content-Type header, checks nothing real
  - saves the file as is, so a disguised script is stored untouched
  - serves files back with a Content-Type guessed from the extension and no
    anti sniffing header, so an uploaded .html or .svg runs in the browser

What the secure handler does instead is in secure_upload() below.

WARNING: the vulnerable parts are unsafe on purpose. Run only on localhost.
"""

from flask import (Flask, request, redirect, url_for, render_template_string,
                   send_file, abort, Response)
import os
import io
import uuid
import shutil
import mimetypes
from PIL import Image

app = Flask(__name__)

HERE = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(HERE, "uploads")
SEED_DIR = os.path.join(HERE, "seed")

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_BYTES = 3 * 1024 * 1024          # 3 MB cap, enforced by the secure handler
IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}


def reset_uploads():
    """Start each run from the same four seed photos, so the lab repeats."""
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR)
    for f in sorted(os.listdir(SEED_DIR)):
        shutil.copy(os.path.join(SEED_DIR, f), os.path.join(UPLOAD_DIR, f))


reset_uploads()


def ext_of(name):
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

PAGE = """
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aperture</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>

<div class="topbar">
  <div class="brand">
    <span class="mark">Aper<span>ture</span></span>
    <span class="tag">community photo gallery</span>
  </div>
  <div class="modeswitch">
    <a href="{{ url_for('home', mode='vulnerable') }}"
       class="{{ 'on-vuln' if mode=='vulnerable' else '' }}">Vulnerable</a>
    <a href="{{ url_for('home', mode='secure') }}"
       class="{{ 'on-safe' if mode=='secure' else '' }}">Secure</a>
  </div>
</div>

<div class="wrap">

  {% if mode=='vulnerable' %}
  <div class="banner vuln"><span class="dot"></span>
    <div><b>Vulnerable uploader is active.</b> Files are saved using the name
    the browser sent, with no checks on type or content, and served back so the
    browser will run them. This is the attack surface.</div>
  </div>
  {% else %}
  <div class="banner safe"><span class="dot"></span>
    <div><b>Secure uploader is active.</b> Only real images pass, they are
    re-encoded to strip anything hidden inside, renamed to a random name, size
    limited, and served as plain downloads that cannot run.</div>
  </div>
  {% endif %}

  {% if flash %}<div class="flash {{ flash_kind }}">{{ flash|safe }}</div>{% endif %}

  <div class="uploader">
    <h2>Share a photo</h2>
    <p class="hint">JPG or PNG from your last trip. It appears in the gallery
      straight away.</p>
    <form class="drop" method="post" enctype="multipart/form-data"
          action="{{ '/upload' if mode=='vulnerable' else '/secure/upload' }}">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.6" stroke-linecap="round"
        stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
      <div class="fields">
        <input type="file" name="file" required>
        <input type="text" name="caption" placeholder="Caption (optional)">
        <button class="btn block">Upload photo</button>
      </div>
    </form>
  </div>

  <div class="sectionhead">
    <h1>The gallery</h1>
    <span class="count">{{ files|length }} items</span>
  </div>

  <div class="grid">
    {% for f in files %}
    <div class="card">
      {% if f.is_image %}
      <div class="thumb"><img src="/uploads/{{ f.name }}" alt="{{ f.name }}"></div>
      {% else %}
      <div class="thumb file">
        <div class="ext">.{{ f.ext or 'file' }}</div>
        <div>not an image</div>
      </div>
      {% endif %}
      <div class="meta">
        <span class="name" title="{{ f.name }}">{{ f.name }}</span>
        <a href="/uploads/{{ f.name }}" target="_blank">open</a>
      </div>
    </div>
    {% endfor %}
  </div>
</div>

<footer>Aperture is a teaching app for the file upload security practical.
Do not deploy it. Mode: {{ mode }}.</footer>
</body></html>
"""


def list_files():
    items = []
    for name in sorted(os.listdir(UPLOAD_DIR)):
        e = ext_of(name)
        items.append({"name": name, "ext": e, "is_image": e in IMAGE_EXT})
    return items


@app.route("/")
def home():
    mode = request.args.get("mode", "vulnerable")
    if mode not in ("vulnerable", "secure"):
        mode = "vulnerable"
    flash = request.args.get("flash", "")
    flash_kind = request.args.get("kind", "good")
    return render_template_string(PAGE, mode=mode, files=list_files(),
                                  flash=flash, flash_kind=flash_kind)


# ---------------------------------------------------------------------------
# VULNERABLE upload
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return redirect(url_for("home", mode="vulnerable"))

    # VULNERABLE: the browser supplied filename is trusted and joined straight
    # onto the upload path. A name like ../../x escapes the uploads folder.
    filename = f.filename
    dest = os.path.join(UPLOAD_DIR, filename)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    f.save(dest)

    msg = (f"Saved <code>{filename}</code> "
           f"(declared type: {f.mimetype}). No checks were run.")
    return redirect(url_for("home", mode="vulnerable", flash=msg, kind="warn"))


# ---------------------------------------------------------------------------
# SECURE upload
# ---------------------------------------------------------------------------

@app.route("/secure/upload", methods=["POST"])
def secure_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return redirect(url_for("home", mode="secure"))

    # Layer 1: size limit. Read the stream once, cap it.
    data = f.read()
    if len(data) > MAX_BYTES:
        return redirect(url_for("home", mode="secure",
                        flash="Rejected: file is larger than 3 MB.", kind="warn"))

    # Layer 2: extension allowlist (not a blocklist). Only these may pass.
    ext = ext_of(f.filename)
    if ext not in ALLOWED_EXT:
        return redirect(url_for("home", mode="secure",
                        flash=f"Rejected: .{ext or 'unknown'} is not an allowed "
                              "image type.", kind="warn"))

    # Layer 3: verify the bytes really are an image, ignoring the name and the
    # Content-Type. Pillow parses the data and fails on anything that is not a
    # real image, which stops a script renamed to .png.
    try:
        probe = Image.open(io.BytesIO(data))
        probe.verify()
    except Exception:
        return redirect(url_for("home", mode="secure",
                        flash="Rejected: the file is not a valid image, whatever "
                              "its name says.", kind="warn"))

    # Layer 4: re-encode the image. Opening and re-saving produces a clean file
    # built from pixels only, so any script, HTML or polyglot hidden in the
    # original bytes or metadata is discarded.
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return redirect(url_for("home", mode="secure",
                        flash="Rejected: could not process the image.", kind="warn"))

    # Layer 5: throw away the user's filename. Generate our own random one with
    # a safe extension. This defeats path traversal, double extensions and
    # overwriting another file.
    safe_name = f"{uuid.uuid4().hex}.jpg"
    img.save(os.path.join(UPLOAD_DIR, safe_name), format="JPEG", quality=88)

    msg = (f"Accepted and re-encoded as <code>{safe_name}</code>. "
           "Original name and any hidden content were discarded.")
    return redirect(url_for("home", mode="secure", flash=msg, kind="good"))


# ---------------------------------------------------------------------------
# Serving uploaded files
# ---------------------------------------------------------------------------

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # VULNERABLE serving: the content type is guessed from the extension and no
    # anti sniffing header is sent, so an uploaded .html or .svg is handed to
    # the browser as runnable content.
    full = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(full):
        abort(404)
    ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
    with open(full, "rb") as fh:
        body = fh.read()
    return Response(body, mimetype=ctype)


# A tiny read only helper the attack script uses to prove what is on disk.
@app.route("/debug/list")
def debug_list():
    import json
    out = {"uploads": sorted(os.listdir(UPLOAD_DIR))}
    return app.response_class(json.dumps(out), mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
