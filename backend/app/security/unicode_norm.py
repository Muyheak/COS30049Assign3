"""Detection-evasion defence (section 2.8): fold look-alike text back to ASCII.

The model's features are ASCII string matches ("login", "paypal", ".", digits).
A phisher can keep a URL looking identical to a person while changing what the
model sees:
  * homoglyphs        pаypal  (Cyrillic а, U+0430) no longer contains "paypal"
  * fullwidth forms   ｌｏｇｉｎ  and fullwidth dots ．
  * invisible chars   log​in (zero-width space) breaks the substring match
  * punycode          xn--pypal-4ve.com, the form a browser actually sends
  * percent-encoding  %D0%B0 hides the homoglyph until it is decoded

`skeletonise` reduces all of these to one canonical ASCII "skeleton" (in the
spirit of Unicode TS #39 confusable skeletons) before feature extraction.
"""
import re
import unicodedata
from urllib.parse import unquote

# Characters that render (near) identically to an ASCII letter in common fonts.
# Source: Unicode confusables.txt (TS #39), restricted to Cyrillic, Greek,
# Armenian and Latin-extended letters that map to a single ASCII letter.
_CONFUSABLES = {
    # Cyrillic lower
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i",
    "ј": "j", "к": "k", "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r",
    "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "ź": "z",
    # Cyrillic upper (lower-cased later by normalize for the host; mapped here for the path)
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y", "Ԝ": "W",
    # Greek
    "α": "a", "β": "b", "ϲ": "c", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
    # Armenian and Latin extended
    "օ": "o", "ս": "u", "ց": "g", "հ": "h", "ո": "n", "ı": "i", "ɑ": "a", "ɡ": "g", "ʟ": "l",
    "ɩ": "i", "ℓ": "l", "ꞵ": "b",
}
_TABLE = str.maketrans(_CONFUSABLES)
_HOST_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)?([^/?#]*)(.*)$", re.S)


def _decode_punycode_host(host):
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass  # malformed punycode: keep as-is, the model sees the raw label
        labels.append(label)
    return ".".join(labels)


def skeletonise(url: str) -> str:
    # 1. decode percent-encoding first, so encoded homoglyphs are visible to the steps below
    url = unquote(url)
    # 2. drop invisible "format" characters: zero-width spaces/joiners, bidi controls, soft hyphen
    url = "".join(ch for ch in url if unicodedata.category(ch) != "Cf")
    # 3. NFKC folds fullwidth letters, digits, dots and slashes to ASCII
    url = unicodedata.normalize("NFKC", url)
    # 4. punycode labels in the host back to Unicode, so step 5 can see their homoglyphs
    m = _HOST_RE.match(url)
    if m:
        scheme, host, rest = m.groups()
        url = (scheme or "") + _decode_punycode_host(host) + rest
    # 5. strip accents (é -> e) and map look-alike letters to ASCII
    url = "".join(ch for ch in unicodedata.normalize("NFKD", url) if unicodedata.category(ch) != "Mn")
    return url.translate(_TABLE)
