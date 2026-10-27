# Norbu Electronics, SQL Injection Lab

A small online store for the Software Security practical "Set up a vulnerable web
application and perform various types of SQL injection attacks". Every feature
has a vulnerable version and a secure version at the same path under `/secure/`.

Insecure on purpose. Run only on your own machine, on localhost.

## Files

- `app.py` - the store, vulnerable and secure routes side by side (port 5000)
- `database.py` - builds a fresh SQLite database on every start
- `static/` - the storefront styling and product images
- `attacks.py` - runs all seven attacks and prints what each one did
- `LAB_REPORT.md` - the report
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

Open http://127.0.0.1:5000. Try the login with `admin'-- ` as the username, or
run `python3 attacks.py` in another terminal to see everything at once.

## Attacks covered

Authentication bypass, error based disclosure, UNION extraction (numeric and
string context), boolean blind, time based blind, stacked queries, and second
order injection. Out of band is explained in the report but not run, since it
needs network features the local SQLite setup does not have.

## The secure routes

Parameterised queries everywhere, plus input validation on numeric ids, single
statement execution to stop stacking, and hidden database errors.
