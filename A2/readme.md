
# NetGuard Tools, Command Injection Lab

A server operations console for the Software Security practical "Create a command
line interface in a web application and implement safeguards against command
injection". Each tool has a vulnerable version and a secure version at
`/secure/...`.

Insecure on purpose, and it runs commands as the user that starts it. Run only
on your own machine, on localhost.

## Files

- `app.py` - the console, vulnerable and secure tools (port 5001)
- `static/style.css` - the console styling
- `attacks.py` - runs all the attacks and prints what each one did
- `appdata/` - sample files the backup tool archives
- `LAB_REPORT.docx` / `.pdf` / `.md` - the report (submit the docx)
- `RECREATE_STEPS.md` - how to run it and take your own screenshots
- `attack_output.txt` - saved output of a real run
- `screenshots/` - the screenshots used in the report

## Setup

```
pip install flask requests
```

On Kali use a venv: `python3 -m venv venv && source venv/bin/activate && pip install flask requests`

## Run

```
python3 app.py
```

Open http://127.0.0.1:5001. In the Host lookup tool, type `localhost; id` to run
a command, or run `python3 attacks.py` in another terminal to see everything.

## Attacks covered

Command separators (`;` `&&` `||` `|` newline), command substitution (`$( )` and
backticks), reading a sensitive file, blind time based injection, and blind file
write. Out of band is explained in the report but not run, since it needs
outbound network access.

## The secure tools

No shell (arguments passed as a list with `shell=False`) plus an input allowlist.
Each attack is stopped by the first layer that applies to it.
