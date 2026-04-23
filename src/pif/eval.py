"""
Evaluation harness for the detection engine.
Splits the corpus into train/test, rebuilds the semantic index from train only,
then measures precision/recall/F1/ROC-AUC on held-out examples.

Usage:
  python -m pif.eval
  python -m pif.eval --threshold 0.7 --test-ratio 0.2 --sweep
  python -m pif.eval --save-baseline
  python -m pif.eval --compare-baseline
"""
from __future__ import annotations

import asyncio
import json
import random
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from rich.console import Console
from rich.table import Table
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from pif.detection import engine, semantic
from pif.models import settings

console = Console()

_BASELINE_PATH = Path(__file__).parent.parent.parent / "tests" / "eval_baseline.json"
_BASELINE_TOLERANCE = 0.03  # F1 may not drop more than this vs baseline


@dataclass
class EvalExample:
    text: str
    label: bool  # True = injection
    attack_type: str = "benign"


@dataclass
class LayerStats:
    count: int = 0
    latencies: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        return float(np.percentile(self.latencies, 50)) if self.latencies else 0.0

    @property
    def p95(self) -> float:
        return float(np.percentile(self.latencies, 95)) if self.latencies else 0.0


@dataclass
class TypeStats:
    total: int = 0
    detected: int = 0
    confidences: list[float] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.detected / self.total if self.total else 0.0

    @property
    def avg_confidence(self) -> float:
        return float(np.mean(self.confidences)) if self.confidences else 0.0


@dataclass
class EvalResult:
    precision: float
    recall: float
    f1: float
    roc_auc: float
    accuracy: float
    tp: int
    fp: int
    tn: int
    fn: int
    n_injection: int
    n_benign: int
    threshold: float
    heuristic_layer: LayerStats
    semantic_layer: LayerStats
    per_type: dict[str, TypeStats]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "roc_auc": round(self.roc_auc, 4),
            "accuracy": round(self.accuracy, 4),
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "threshold": self.threshold,
            "n_injection": self.n_injection,
            "n_benign": self.n_benign,
        }


def load_corpus(corpus_path: str) -> list[EvalExample]:
    path = Path(corpus_path)
    examples: list[EvalExample] = []

    injections_file = path / "injections.jsonl"
    if injections_file.exists():
        with open(injections_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                text = obj.get("text", "")
                if text:
                    examples.append(
                        EvalExample(text=text, label=True, attack_type=obj.get("type", "direct_injection"))
                    )

    benign_file = path / "benign.jsonl"
    if benign_file.exists():
        with open(benign_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                text = obj.get("text", "")
                if text:
                    examples.append(EvalExample(text=text, label=False, attack_type="benign"))

    return examples


def split(
    examples: list[EvalExample], test_ratio: float = 0.2, seed: int = 42
) -> tuple[list[EvalExample], list[EvalExample]]:
    """Stratified split by label."""
    rng = random.Random(seed)
    injections = [e for e in examples if e.label]
    benign = [e for e in examples if not e.label]

    rng.shuffle(injections)
    rng.shuffle(benign)

    n_inj_test = max(1, int(len(injections) * test_ratio))
    n_ben_test = max(1, int(len(benign) * test_ratio))

    test = injections[:n_inj_test] + benign[:n_ben_test]
    train = injections[n_inj_test:] + benign[n_ben_test:]

    return train, test


def _write_temp_corpus(train: list[EvalExample], tmpdir: str) -> str:
    path = Path(tmpdir)
    inj = [e for e in train if e.label]
    ben = [e for e in train if not e.label]

    with open(path / "injections.jsonl", "w") as f:
        for e in inj:
            f.write(json.dumps({"text": e.text, "type": e.attack_type}) + "\n")

    with open(path / "benign.jsonl", "w") as f:
        for e in ben:
            f.write(json.dumps({"text": e.text, "type": "benign"}) + "\n")

    return str(path)


async def _eval_example(
    example: EvalExample, threshold: float, corpus_path: str
) -> tuple[bool, float, int, float]:
    """Returns (predicted, confidence, layer_triggered, latency_ms)."""
    messages = [{"role": "user", "content": example.text}]
    result = await engine.analyze(messages, threshold=threshold, corpus_path=corpus_path)
    return result.is_injection, result.confidence, result.layer_triggered, result.latency_ms


async def evaluate(
    train: list[EvalExample],
    test: list[EvalExample],
    threshold: float,
) -> EvalResult:
    notes: list[str] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        train_corpus = _write_temp_corpus(train, tmpdir)

        # Swap corpus to train-only so semantic layer doesn't see test examples.
        # Reset inside the with-block so stale embeddings aren't accessible after tmpdir is deleted.
        semantic.reset_corpus_embeddings_only()

        # Force-load the train corpus directly — don't rely on a warmup request which
        # may hit the heuristic fast-path and never touch the semantic layer.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, semantic._load_corpus, train_corpus)

        y_true: list[int] = []
        y_pred: list[int] = []
        y_score: list[float] = []
        heuristic_stats = LayerStats()
        semantic_stats = LayerStats()
        per_type: dict[str, TypeStats] = {}

        tasks = [_eval_example(e, threshold, train_corpus) for e in test]
        results = await asyncio.gather(*tasks)

        for example, (predicted, confidence, layer, latency_ms) in zip(test, results):
            y_true.append(int(example.label))
            y_pred.append(int(predicted))
            y_score.append(confidence)

            if layer == 1:
                heuristic_stats.count += 1
                heuristic_stats.latencies.append(latency_ms)
            elif layer == 2:
                semantic_stats.count += 1
                semantic_stats.latencies.append(latency_ms)

            if example.label:
                t = example.attack_type
                if t not in per_type:
                    per_type[t] = TypeStats()
                per_type[t].total += 1
                per_type[t].confidences.append(confidence)
                if predicted:
                    per_type[t].detected += 1

        # Reset inside the with-block before tmpdir is deleted
        semantic.reset_corpus_embeddings_only()

    arr_true = np.array(y_true)
    arr_pred = np.array(y_pred)
    arr_score = np.array(y_score)

    tp = int(np.sum((arr_true == 1) & (arr_pred == 1)))
    fp = int(np.sum((arr_true == 0) & (arr_pred == 1)))
    tn = int(np.sum((arr_true == 0) & (arr_pred == 0)))
    fn = int(np.sum((arr_true == 1) & (arr_pred == 0)))

    n_benign_test = int(np.sum(arr_true == 0))
    if n_benign_test < 30:
        notes.append(
            f"Only {n_benign_test} benign test examples — FP rate has high variance. "
            "Precision numbers are noisy until issue #3 (corpus expansion) lands."
        )

    has_crescendo = any(e.attack_type == "multi_turn_crescendo" for e in test)
    if not has_crescendo:
        notes.append(
            "multi_turn_crescendo not in test set — corpus is single-turn; "
            "crescendo recall is unmeasurable here (see issue #5)."
        )

    roc_auc = 0.0
    if len(set(y_true)) > 1:
        roc_auc = float(roc_auc_score(arr_true, arr_score))

    precision = float(precision_score(arr_true, arr_pred, zero_division=0))
    recall = float(recall_score(arr_true, arr_pred, zero_division=0))
    f1 = float(f1_score(arr_true, arr_pred, zero_division=0))
    accuracy = float(np.mean(arr_true == arr_pred))

    return EvalResult(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        roc_auc=round(roc_auc, 4),
        accuracy=round(accuracy, 4),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        n_injection=int(np.sum(arr_true == 1)),
        n_benign=n_benign_test,
        threshold=threshold,
        heuristic_layer=heuristic_stats,
        semantic_layer=semantic_stats,
        per_type=per_type,
        notes=notes,
    )


async def sweep(
    train: list[EvalExample],
    test: list[EvalExample],
    thresholds: list[float] | None = None,
) -> list[tuple[float, EvalResult]]:
    if thresholds is None:
        thresholds = [round(t, 2) for t in np.arange(0.30, 0.96, 0.05)]
    return [(t, await evaluate(train, test, threshold=t)) for t in thresholds]


def print_report(result: EvalResult) -> None:
    console.print()
    console.rule(f"[bold]PIF Eval — threshold={result.threshold}")
    console.print(
        f"  Test set: [cyan]{result.n_injection}[/cyan] injection, "
        f"[cyan]{result.n_benign}[/cyan] benign "
        f"([dim]{result.n_injection + result.n_benign} total[/dim])"
    )
    console.print()

    # Overall metrics
    metrics = Table(show_header=True, header_style="bold")
    metrics.add_column("Metric", style="dim", width=12)
    metrics.add_column("Value", width=8)
    metrics.add_row("Precision", f"{result.precision:.4f}")
    metrics.add_row("Recall", f"{result.recall:.4f}")
    metrics.add_row("F1", f"[bold]{result.f1:.4f}[/bold]")
    metrics.add_row("ROC-AUC", f"{result.roc_auc:.4f}")
    metrics.add_row("Accuracy", f"{result.accuracy:.4f}")
    metrics.add_section()
    metrics.add_row("TP", str(result.tp))
    metrics.add_row("FP", f"[{'red' if result.fp else 'green'}]{result.fp}[/{'red' if result.fp else 'green'}]")
    metrics.add_row("TN", str(result.tn))
    metrics.add_row("FN", f"[{'red' if result.fn else 'green'}]{result.fn}[/{'red' if result.fn else 'green'}]")
    console.print(metrics)
    console.print()

    # Per-attack-type breakdown
    if result.per_type:
        type_table = Table(show_header=True, header_style="bold magenta")
        type_table.add_column("Attack Type", width=28)
        type_table.add_column("Test N", width=8)
        type_table.add_column("Detected", width=10)
        type_table.add_column("Recall", width=8)
        type_table.add_column("Avg Conf", width=10)

        for attack_type, stats in sorted(result.per_type.items()):
            recall_color = "green" if stats.recall >= 0.8 else ("yellow" if stats.recall >= 0.5 else "red")
            type_table.add_row(
                attack_type,
                str(stats.total),
                str(stats.detected),
                f"[{recall_color}]{stats.recall:.2f}[/{recall_color}]",
                f"{stats.avg_confidence:.3f}",
            )

        console.print(type_table)
        console.print()

    # Latency
    lat = Table(show_header=True, header_style="bold blue")
    lat.add_column("Layer", width=20)
    lat.add_column("Calls", width=8)
    lat.add_column("p50 (ms)", width=10)
    lat.add_column("p95 (ms)", width=10)

    lat.add_row(
        "heuristic (L1)",
        str(result.heuristic_layer.count),
        f"{result.heuristic_layer.p50:.1f}",
        f"{result.heuristic_layer.p95:.1f}",
    )
    lat.add_row(
        "semantic (L2)",
        str(result.semantic_layer.count),
        f"{result.semantic_layer.p50:.1f}",
        f"{result.semantic_layer.p95:.1f}",
    )
    console.print(lat)

    if result.notes:
        console.print()
        for note in result.notes:
            console.print(f"  [yellow]⚠[/yellow]  [dim]{note}[/dim]")
    console.print()


def print_sweep(sweep_results: list[tuple[float, EvalResult]]) -> None:
    console.print()
    console.rule("[bold]Threshold Sweep")
    sweep_table = Table(show_header=True, header_style="bold")
    sweep_table.add_column("Threshold", width=12)
    sweep_table.add_column("Precision", width=12)
    sweep_table.add_column("Recall", width=10)
    sweep_table.add_column("F1", width=10)
    sweep_table.add_column("ROC-AUC", width=10)
    sweep_table.add_column("FP", width=6)
    sweep_table.add_column("FN", width=6)

    best_f1 = max(r.f1 for _, r in sweep_results)
    for threshold, r in sweep_results:
        style = "bold green" if r.f1 == best_f1 else ""
        sweep_table.add_row(
            f"[{style}]{threshold:.2f}[/{style}]" if style else f"{threshold:.2f}",
            f"{r.precision:.4f}",
            f"{r.recall:.4f}",
            f"[{style}]{r.f1:.4f}[/{style}]" if style else f"{r.f1:.4f}",
            f"{r.roc_auc:.4f}",
            str(r.fp),
            str(r.fn),
        )
    console.print(sweep_table)
    console.print()


def compare_baseline(result: EvalResult) -> bool:
    """Returns True if result passes baseline comparison (or no baseline exists)."""
    if not _BASELINE_PATH.exists():
        console.print("[dim]No baseline found — skipping comparison.[/dim]")
        return True

    with open(_BASELINE_PATH) as f:
        baseline = json.load(f)

    baseline_f1 = baseline.get("f1", 0.0)
    drop = baseline_f1 - result.f1

    if drop > _BASELINE_TOLERANCE:
        console.print(
            f"[red bold]REGRESSION:[/red bold] F1 dropped {drop:.4f} "
            f"(baseline={baseline_f1:.4f}, current={result.f1:.4f}, tolerance={_BASELINE_TOLERANCE})"
        )
        return False

    if drop > 0:
        console.print(f"[yellow]F1 down {drop:.4f} vs baseline (within tolerance)[/yellow]")
    else:
        console.print(f"[green]F1 {result.f1:.4f} (+{-drop:.4f} vs baseline {baseline_f1:.4f})[/green]")

    return True


def save_baseline(result: EvalResult) -> None:
    _BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_BASELINE_PATH, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    console.print(f"[green]Baseline saved to {_BASELINE_PATH}[/green]")


async def _main(
    threshold: float,
    test_ratio: float,
    seed: int,
    do_sweep: bool,
    save_baseline_flag: bool,
    compare_baseline_flag: bool,
    json_output: bool,
) -> int:
    corpus_path = settings.corpus_path
    examples = load_corpus(corpus_path)

    if not examples:
        console.print(f"[red]No examples found at {corpus_path}[/red]")
        return 1

    n_inj = sum(1 for e in examples if e.label)
    n_ben = sum(1 for e in examples if not e.label)
    console.print(f"[dim]Corpus: {n_inj} injection, {n_ben} benign[/dim]")

    train, test = split(examples, test_ratio=test_ratio, seed=seed)
    console.print(
        f"[dim]Split (seed={seed}): {len(train)} train, {len(test)} test ({test_ratio:.0%} held out)[/dim]"
    )

    if do_sweep:
        sweep_results = await sweep(train, test)
        print_sweep(sweep_results)
        # Best-F1 result used for baseline/comparison — threshold stored in result.to_dict()
        _, result = max(sweep_results, key=lambda x: x[1].f1)
        if json_output:
            import sys
            rows = [{"threshold": t, **r.to_dict()} for t, r in sweep_results]
            json.dump(rows, sys.stdout, indent=2)
            print()
        else:
            print_report(result)
    else:
        result = await evaluate(train, test, threshold=threshold)
        if json_output:
            import sys
            json.dump(result.to_dict(), sys.stdout, indent=2)
            print()
        else:
            print_report(result)

    if save_baseline_flag:
        save_baseline(result)

    passed = True
    if compare_baseline_flag:
        passed = compare_baseline(result)

    return 0 if passed else 1


def main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="PIF detection eval harness")
    parser.add_argument("--threshold", type=float, default=settings.block_threshold)
    parser.add_argument("--test-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sweep", action="store_true", help="Sweep thresholds 0.30–0.95")
    parser.add_argument("--save-baseline", action="store_true", help="Save result as baseline")
    parser.add_argument("--compare-baseline", action="store_true", help="Compare against saved baseline")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    exit_code = asyncio.run(
        _main(
            threshold=args.threshold,
            test_ratio=args.test_ratio,
            seed=args.seed,
            do_sweep=args.sweep,
            save_baseline_flag=args.save_baseline,
            compare_baseline_flag=args.compare_baseline,
            json_output=args.json,
        )
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
