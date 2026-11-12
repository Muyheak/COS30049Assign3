"""Live, on-camera version of the evasion attack: sends one real phishing URL from
the dataset (held out from training) and four disguised copies to the running API.

Run once with the server started as UNICODE_NORMALISATION=off (attack works),
then again with it on (attack fails). The disguised URLs look the same on
screen; the escapes below show what is really inside them.
"""
import httpx

BASE = "http://127.0.0.1:8000"
ORIGINAL = "https://kucoinloginhua.webflow.io/"
VARIANTS = {
    "original": ORIGINAL,
    # Cyrillic а е і о р с у һ ԁ ӏ ԝ in place of Latin letters
    "homoglyph": "https://kuсоіnӏоgіnһuа.ԝеbfӏоԝ.іо/",
    # invisible zero-width space inside "login"
    "zero_width": "https://kucoinlo​ginhua.webflow.io/",
    # FULLWIDTH FULL STOP, which browsers treat as an ordinary dot
    "fullwidth": "https://kucoinloginhua．webflow．io/",
}
# the homoglyph host as a browser actually sends it (IDNA/punycode form)
_host = VARIANTS["homoglyph"].split("/")[2]
VARIANTS["punycode"] = "https://" + _host.encode("idna").decode() + "/"

with httpx.Client() as c:
    print(f"{'variant':<11} {'shown as':<45} {'verdict':<11} {'p(phish)':>8}  normalised?")
    for name, url in VARIANTS.items():
        r = c.post(f"{BASE}/api/v1/check", json={"url": url}).json()
        print(f"{name:<11} {url[:44]:<45} {r['label']:<11} {r['phishing_probability']:>8.3f}  {r['unicode_normalised']}")
