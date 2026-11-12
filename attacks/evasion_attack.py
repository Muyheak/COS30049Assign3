"""Detection-evasion attack (section 2.8), measured before and after the defence.

Threat: a phisher edits a URL the model already catches so that it LOOKS the
same to a person but no longer matches the ASCII features the model counts.

Data: phishing URLs from features_combined.csv that were NOT in the model's
200,000-row training sample, and that the model correctly flags. For each, we
build disguised variants and record whether the model still flags them:

  homoglyph   Latin letters in the host/path -> identical-looking Cyrillic/Greek
  zero_width  invisible U+200B inserted inside suspicious words and brand names
  fullwidth   host dots -> FULLWIDTH FULL STOP (U+FF0E), which browsers treat as "."
  punycode    homoglyph host sent in its xn-- (IDNA) form, as a browser sends it
  adaptive    the attacker tries all four and keeps any that evades

Evasion rate = share of detected phishing URLs that are classed legitimate
after the disguise. Measured over 5 independent samples (seeds) so results are
reported as mean +/- sd, for three pipelines:
  none        raw input (the original A2 pipeline)
  nfkc_only   the "obvious" fix: Unicode NFKC normalisation only
  skeleton    our defence: app/security/unicode_norm.skeletonise

Cost: false-positive rate on held-out legitimate URLs with/without the
defence, prediction flips on genuine non-ASCII (IDN) domains, and the
per-URL time the defence adds.

Usage:  python attacks/evasion_attack.py path/to/features_combined.csv.gz
"""
import json
import random
import statistics
import sys
import time
import unicodedata
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.features import FEATURES, companies, extract_features, normalize, suspicious_words  # noqa: E402
from app.model import load_model  # noqa: E402  (verifies the model hash before unpickling)
from app.security.unicode_norm import skeletonise  # noqa: E402

LOOKALIKE = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і",
             "s": "ѕ", "j": "ј", "h": "һ", "d": "ԁ", "l": "ӏ", "w": "ԝ"}
TARGETS = sorted(set(suspicious_words + companies), key=len, reverse=True)
SEEDS = [1, 2, 3, 4, 5]
N_PER_SEED = 1000


def split_url(u):
    scheme, sep, rest = u.partition("://")
    if not sep:
        scheme, rest = "", u
    cut = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1] or [len(rest)])
    return (scheme + "://" if sep else ""), rest[:cut], rest[cut:]


def homoglyph(u, rng):
    """Swap every look-alike letter after the scheme (hides 'paypal', 'login', '.tk', ...)."""
    s, host, rest = split_url(u)
    return s + "".join(LOOKALIKE.get(ch, ch) for ch in host + rest)


def zero_width(u, rng):
    low = u.lower()
    out = u
    for w in TARGETS:
        idx = low.find(w)
        if idx != -1:
            mid = idx + len(w) // 2
            out = out[:mid] + "​" + out[mid:]
            low = low[:mid] + "​" + low[mid:]
    return out


def fullwidth(u, rng):
    s, host, rest = split_url(u)
    return s + host.replace(".", "．") + rest


def punycode(u, rng):
    s, host, rest = split_url(u)
    labels = []
    for label in host.split("."):
        fake = "".join(LOOKALIKE.get(ch, ch) for ch in label)
        if fake != label:
            try:
                fake = fake.encode("idna").decode("ascii")
            except UnicodeError:
                fake = label
        labels.append(fake)
    return s + ".".join(labels) + rest


ATTACKS = {"homoglyph": homoglyph, "zero_width": zero_width, "fullwidth": fullwidth, "punycode": punycode}
PIPELINES = {
    "none": lambda u: u,
    "nfkc_only": lambda u: unicodedata.normalize("NFKC", u),
    "skeleton": skeletonise,
}


def predict_many(model, urls, pre):
    rows = []
    for u in urls:
        f = extract_features(normalize(pre(u)))
        rows.append([f[k] for k in FEATURES])
    return model.predict_proba(pd.DataFrame(rows, columns=FEATURES))[:, 1] >= 0.5


def main(csv_path):
    model = load_model()
    df = pd.read_csv(csv_path, usecols=["url", "label"] + FEATURES).dropna(subset=FEATURES)
    train_idx = df.sample(200_000, random_state=42).index      # same sample train_model.py used
    held = df.drop(train_idx)
    phish = held[held.label == 1].url.astype(str).tolist()
    legit = held[held.label == 0].url.astype(str).tolist()

    results = {a: {p: [] for p in PIPELINES} for a in list(ATTACKS) + ["adaptive"]}
    detected_counts = []
    for seed in SEEDS:
        rng = random.Random(seed)
        pool = rng.sample(phish, 6000)
        caught = [u for u, hit in zip(pool, predict_many(model, pool, lambda x: x)) if hit][:N_PER_SEED]
        detected_counts.append(len(caught))
        variants = {a: [fn(u, rng) for u in caught] for a, fn in ATTACKS.items()}
        for p, pre in PIPELINES.items():
            still = {a: predict_many(model, v, pre) for a, v in variants.items()}
            for a in ATTACKS:
                results[a][p].append(100 * (1 - still[a].mean()))
            # adaptive: evades if ANY variant evades
            evaded_any = ~(still["homoglyph"] & still["zero_width"] & still["fullwidth"] & still["punycode"])
            results["adaptive"][p].append(100 * evaded_any.mean())
        print(f"seed {seed}: {len(caught)} detected phishing URLs attacked")

    print("\nEVASION RATE (% of detected phishing URLs now classed legitimate), mean +/- sd over 5 seeds")
    print(f"{'attack':<12}" + "".join(f"{p:>18}" for p in PIPELINES))
    table = {}
    for a, by_p in results.items():
        cells = []
        for p in PIPELINES:
            m, sd = statistics.mean(by_p[p]), statistics.stdev(by_p[p])
            table.setdefault(a, {})[p] = {"mean": round(m, 2), "sd": round(sd, 2), "runs": [round(x, 2) for x in by_p[p]]}
            cells.append(f"{m:>11.1f} +/- {sd:<4.1f}")
        print(f"{a:<12}" + "".join(cells))

    # ---- Cost 1: does the defence hurt legitimate URLs? ----
    rng = random.Random(99)
    legit_s = rng.sample(legit, 20000)
    fp_raw = predict_many(model, legit_s, PIPELINES["none"]).mean() * 100
    fp_def = predict_many(model, legit_s, skeletonise).mean() * 100
    changed = sum(skeletonise(u) != u for u in legit_s)
    print(f"\nCOST: false-positive rate on 20,000 held-out legitimate URLs: {fp_raw:.2f}% raw -> {fp_def:.2f}% with defence"
          f" ({changed} of them altered by normalisation)")

    # ---- Cost 2: genuine internationalised domains get folded to ASCII ----
    idn = ["https://münchen.de/", "https://bücher.de/", "https://xn--mnchen-3ya.de/", "https://café.fr/menu",
           "https://россия.рф/", "https://ελλάδα.gr/", "https://日本.jp/", "https://köln.de/login"]
    print("\nCOST: genuine non-ASCII domains (what the model sees, raw -> defended):")
    for u in idn:
        r, d = predict_many(model, [u], PIPELINES["none"])[0], predict_many(model, [u], skeletonise)[0]
        print(f"   {u:<32} {skeletonise(u):<34} {'phish' if r else 'legit'} -> {'phish' if d else 'legit'}")

    # ---- Cost 3: latency ----
    sample = legit_s[:5000]
    t = time.perf_counter(); [skeletonise(u) for u in sample]; per = (time.perf_counter() - t) / len(sample) * 1e6
    print(f"\nCOST: skeletonise adds {per:.1f} microseconds per URL (model inference is ~2,000)")

    out = ROOT / "results" / "evasion_results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"evasion_rate_pct": table, "detected_per_seed": detected_counts,
                               "false_positive_pct": {"raw": round(fp_raw, 2), "defended": round(fp_def, 2)},
                               "skeleton_us_per_url": round(per, 1)}, indent=2))
    print(f"\nSaved {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "features_combined.csv")
