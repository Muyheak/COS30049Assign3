"""Denial-of-service attack against our OWN API, run on our own machine only.

While each attack runs, a separate "victim" process (a normal user) keeps
calling the API, and we record how long the victim waits. The victim runs in
its own process so the attacker's own CPU load cannot distort its timings.

  expensive  One request with a huge JSON body (default 150 MB). Without the
             body cap the server reads and json-parses all of it on the event
             loop before Pydantic rejects it, so every other user waits.
  flood      Many /check requests at once. Without admission control every
             request queues on the event loop; with it the excess gets 503 fast.

Usage (server already running on :8000):
    python attacks/dos_attack.py expensive
    python attacks/dos_attack.py flood --requests 3000 --concurrency 300
    python attacks/dos_attack.py flood --csv results/flood_on.csv   # save per-probe timings
"""
import argparse
import asyncio
import csv
import multiprocessing as mp
import statistics
import time
from collections import Counter

import httpx

BASE = "http://127.0.0.1:8000"
URL_SAMPLE = "http://paypal.com.secure-login.tk/verify/account?id=12345"


def victim_process(path, stop, out):
    """Normal user: one request every 50 ms until told to stop."""
    async def loop():
        lat = []
        async with httpx.AsyncClient() as c:
            while not stop.is_set():
                t = time.perf_counter()
                try:
                    if path == "health":
                        r = await c.get(f"{BASE}/api/v1/health", timeout=60)
                    else:
                        r = await c.post(f"{BASE}/api/v1/check", json={"url": "https://www.swinburne.edu.au/"},
                                         timeout=60)
                    lat.append(((time.perf_counter() - t) * 1000, r.status_code))
                except httpx.HTTPError:
                    lat.append((float("inf"), 0))
                await asyncio.sleep(0.05)
        return lat
    out.put(asyncio.run(loop()))


class Victim:
    def __init__(self, path="health"):
        self.stop, self.out = mp.Event(), mp.Queue()
        self.p = mp.Process(target=victim_process, args=(path, self.stop, self.out))

    def __enter__(self):
        self.p.start(); time.sleep(0.5); return self

    def __exit__(self, *a):
        self.stop.set(); self.result = self.out.get(); self.p.join()


def summary(name, rows):
    ok = [ms for ms, _ in rows if ms != float("inf")]
    codes = Counter(code for _, code in rows)
    if len(ok) < 2:
        return f"{name}: too few probes ({rows})"
    q = statistics.quantiles(ok, n=100)
    return (f"{name}: n={len(rows)}  median={statistics.median(ok):.1f} ms  p95={q[94]:.1f} ms  "
            f"max={max(ok):.1f} ms  status={dict(codes)}")


def save(path, rows, label):
    if path:
        with open(path, "a", newline="") as f:
            csv.writer(f).writerows([(label, ms, code) for ms, code in rows])


async def expensive(size_mb):
    body = b'{"url": "' + b"a" * (size_mb * 1024 * 1024) + b'"}'
    async with httpx.AsyncClient() as client:
        t = time.perf_counter()
        try:
            r = await client.post(f"{BASE}/api/v1/check", content=body,
                                  headers={"content-type": "application/json"}, timeout=120)
            status = r.status_code
        except httpx.HTTPError as e:
            status = f"{type(e).__name__} (server closed the connection early)"
        await asyncio.sleep(0.5)
    return status, (time.perf_counter() - t - 0.5) * 1000


async def flood(n, concurrency):
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(limits=limits) as client:
        sem, codes, lat = asyncio.Semaphore(concurrency), Counter(), []

        async def one():
            async with sem:
                t = time.perf_counter()
                try:
                    r = await client.post(f"{BASE}/api/v1/check", json={"url": URL_SAMPLE}, timeout=120)
                    codes[r.status_code] += 1
                except httpx.HTTPError as e:
                    codes[type(e).__name__] += 1
                lat.append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        await asyncio.gather(*(one() for _ in range(n)))
        return codes, lat, time.perf_counter() - t


def main():
    p = argparse.ArgumentParser()
    p.add_argument("attack", choices=["expensive", "flood"])
    p.add_argument("--size-mb", type=int, default=150)
    p.add_argument("--requests", type=int, default=3000)
    p.add_argument("--concurrency", type=int, default=300)
    p.add_argument("--victim", choices=["health", "check"], default="health")
    p.add_argument("--csv", help="append victim timings to this CSV")
    a = p.parse_args()

    with Victim(a.victim) as before:
        time.sleep(1.5)
    print(summary(f"Victim {a.victim} with NO attack   ", before.result))

    with Victim(a.victim) as during:
        if a.attack == "expensive":
            status, ms = asyncio.run(expensive(a.size_mb))
            print(f"Attack: one {a.size_mb} MB body -> {status}, answered in {ms:.0f} ms")
        else:
            codes, lat, total = asyncio.run(flood(a.requests, a.concurrency))
            print(f"Attack: {a.requests} /check requests, {a.concurrency} at once, {total:.1f} s -> {dict(codes)}")
            print(f"        attacker median wait {statistics.median(lat):.0f} ms")
    print(summary(f"Victim {a.victim} DURING attack    ", during.result))
    save(a.csv, before.result, "baseline"); save(a.csv, during.result, "attack")


if __name__ == "__main__":
    main()
