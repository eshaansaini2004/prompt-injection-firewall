"""
Concurrency bench for the semantic layer.

The layer is synchronous and runs on asyncio's default thread pool, so the open
question was never single-call latency — it's what happens when requests arrive
together. Distinct texts per call, otherwise the LRU cache answers everything.

    python scripts/bench_semantic.py
    python scripts/bench_semantic.py --levels 1,8,32 --requests 128
"""
import argparse
import asyncio
import statistics
import time

from pif.detection import engine, semantic


def _texts(n: int) -> list[str]:
    # Unique, benign, and long enough to reach layer 2.
    return [f"Summarize the quarterly report for region {i} and list the top three risks." for i in range(n)]


async def _one(text: str) -> float:
    start = time.perf_counter()
    await engine.analyze([{"role": "user", "content": text}])
    return (time.perf_counter() - start) * 1000


async def run(level: int, requests: int) -> None:
    texts = _texts(requests)
    latencies: list[float] = []
    started = time.perf_counter()

    for i in range(0, requests, level):
        batch = texts[i : i + level]
        latencies.extend(await asyncio.gather(*(_one(t) for t in batch)))

    wall = time.perf_counter() - started
    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95) - 1]
    print(
        f"  concurrency {level:>3}  p50 {p50:7.1f}ms  p95 {p95:7.1f}ms  "
        f"throughput {requests / wall:5.1f} req/s"
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--levels", default="1,4,8,16,32")
    parser.add_argument("--requests", type=int, default=64)
    args = parser.parse_args()

    print("Warming up (model load)...")
    await engine.analyze([{"role": "user", "content": "warm up the model"}])
    print(f"{args.requests} requests per level, unique texts, cache cleared between levels\n")

    for level in [int(x) for x in args.levels.split(",")]:
        semantic._encode_cached.cache_clear()
        await run(level, args.requests)


if __name__ == "__main__":
    asyncio.run(main())
