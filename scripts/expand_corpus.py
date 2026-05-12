"""
Corpus expansion via LLM paraphrase generation.

Reads injections.jsonl, calls Claude to generate N paraphrases per example,
writes output to a staging file for manual review before folding into the corpus.

Usage:
    python scripts/expand_corpus.py --n 3 --out staging_expanded.jsonl
    python scripts/expand_corpus.py --type direct_injection --n 5

Review staging_expanded.jsonl, delete anything wrong, then:
    cat staging_expanded.jsonl >> src/pif/detection/corpus/injections.jsonl
    python -m pif.cli reindex
    python -m pif.cli eval --compare-baseline
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _build_prompt(example: str, attack_type: str, n: int) -> str:
    return (
        f"You are building a dataset of prompt injection attack examples "
        f"for training a security classifier.\n\n"
        f"Attack type: {attack_type}\n"
        f"Original example:\n{example}\n\n"
        f"Generate {n} paraphrases of this attack. Each paraphrase must:\n"
        f"- Convey the same attack intent\n"
        f"- Use different phrasing, word order, or framing\n"
        f"- Be plausible as a real-world attack attempt\n\n"
        f"Output ONLY a JSON array of strings, no explanation:\n"
        f'["paraphrase 1", "paraphrase 2", ...]'
    )


def expand(
    corpus_path: Path,
    output_path: Path,
    n: int = 3,
    attack_type_filter: str | None = None,
    max_examples: int | None = None,
    dry_run: bool = False,
) -> None:
    try:
        import anthropic
    except ImportError:
        print("Error: anthropic package not installed. Run: pip install anthropic", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic()

    injections_file = corpus_path / "injections.jsonl"
    if not injections_file.exists():
        print(f"Error: {injections_file} not found", file=sys.stderr)
        sys.exit(1)

    examples: list[dict] = []
    with open(injections_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if attack_type_filter and obj.get("type") != attack_type_filter:
                continue
            examples.append(obj)

    if max_examples:
        examples = examples[:max_examples]

    print(f"Expanding {len(examples)} examples ({n} paraphrases each) → {output_path}")

    if dry_run:
        print("Dry run — no API calls made.")
        return

    generated = 0
    errors = 0

    with open(output_path, "w") as out:
        for i, ex in enumerate(examples, 1):
            prompt = _build_prompt(ex["text"], ex["type"], n)
            try:
                resp = client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = resp.content[0].text.strip()
                paraphrases: list[str] = json.loads(raw)
                for p in paraphrases:
                    if isinstance(p, str) and p.strip():
                        out.write(json.dumps({"text": p.strip(), "type": ex["type"]}) + "\n")
                        generated += 1
                print(f"[{i}/{len(examples)}] {ex['type']}: +{len(paraphrases)} paraphrases")
            except Exception as exc:
                print(f"[{i}/{len(examples)}] Error: {exc}", file=sys.stderr)
                errors += 1
            # Stay under API rate limits
            time.sleep(0.5)

    print(f"\nDone: {generated} examples written to {output_path} ({errors} errors)")
    print(f"Review {output_path}, then run:")
    print(f"  cat {output_path} >> src/pif/detection/corpus/injections.jsonl")
    print(f"  python -m pif.cli reindex && python -m pif.cli eval --compare-baseline")


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand injection corpus via LLM paraphrasing")
    parser.add_argument("--corpus", default="src/pif/detection/corpus", help="Path to corpus directory")
    parser.add_argument("--out", default="staging_expanded.jsonl", help="Output staging file")
    parser.add_argument("--n", type=int, default=3, help="Paraphrases per example")
    parser.add_argument("--type", dest="attack_type", default=None, help="Filter to one attack type")
    parser.add_argument("--max", type=int, default=None, help="Max examples to process")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without calling the API")
    args = parser.parse_args()

    expand(
        corpus_path=Path(args.corpus),
        output_path=Path(args.out),
        n=args.n,
        attack_type_filter=args.attack_type,
        max_examples=args.max,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
