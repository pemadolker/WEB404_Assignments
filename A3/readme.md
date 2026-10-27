# Aperture, Malicious File Upload Lab

A small photo gallery web app for the Software Security practical "Develop a
file upload feature and implement security measures to prevent malicious file
uploads". The upload feature exists in two modes, picked by the switch in the
top right: a vulnerable uploader at `/upload` and a secure uploader at
`/secure/upload`. Everything else about the page is identical.

This app is insecure on purpose. Run it only on your own machine. It binds to
localhost and must never be placed on a real network.

## Files

- `app.py` - the gallery app, vulnerable and secure upload handlers
- `static/style.css` - the interface styling
- `attacks.py` - runs every upload attack and prints what each one did
- `seed/` - the four sample photos the gallery starts with
- `_attackfiles/` - the malicious test files (web shell, XSS html and svg, etc.)
- `LAB_REPORT.md` - the report 
- `attack_output.txt` - saved output of a real attack run
- `screenshots/` - the screenshots used in the report

## Setup

```
pip install flask requests pillow
```

On Kali, make a venv first so pip is allowed:

```
python3 -m venv venv && source venv/bin/activate && pip install flask requests pillow
```

## Run

Terminal 1, start the app:

```
python3 app.py
```

It serves on http://127.0.0.1:5002

Terminal 2, run all the attacks automatically:

```
python3 attacks.py
```

Restart `app.py` to reset the gallery to the four seed photos.

## Attacks covered

1. Disguised executable, double extension (shell.php.png)
2. Content-Type (MIME) spoofing
3. Stored XSS through an uploaded HTML file
4. Stored XSS through an uploaded SVG
5. Path traversal through the filename
6. Overwriting an existing file
7. No size limit (denial of service)

## Secure handler, the layers

Size limit, extension allowlist, real content check with Pillow, full image
re-encode to strip hidden payloads, and a random filename so the user never
controls the name. Each attack above is stopped by the first layer that
applies to it.

## Trying it by hand

- Open the app, leave it in Vulnerable mode.
- Upload `_attackfiles/pwn.html`, then click "open" on it in the gallery. The
  script runs. That is stored XSS through a file upload.
- Switch to Secure mode and upload the same file. It is rejected.
