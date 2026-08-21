"""
CLI entrypoint. `pif start`, `pif reindex`, `pif logs`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="pif", help="Prompt Injection Firewall CLI")
console = Console()


@app.command()
def serve(
    port: int = typer.Option(8000, help="Port to listen on"),
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    reload: bool = typer.Option(False, help="Enable auto-reload (dev mode)"),
) -> None:
    """Start the proxy server."""
    console.print(f"[green]Starting PIF proxy on {host}:{port}[/green]")
    uvicorn.run("pif.proxy:app", host=host, port=port, reload=reload)


def _find_carrier_text_entries(
    corpus_path: Path, threshold: float | None = None
) -> list[tuple[str, str, float]]:
    """
    Find injection entries that are the sole reason their own carrier text blocks.

    An attack example made mostly of ordinary text (a GCG suffix bolted onto "What
    is the capital of France?") sits right next to that harmless question in
    embedding space, so indexing it teaches the semantic layer to flag the question.
    Leave-one-out is what separates those from honest entries: score each opening
    sentence against the corpus with, then without, its own entry. An entry is
    flagged when dropping it takes the carrier below the block threshold *and*
    leaves it sitting closer to the benign corpus — that entry is carrying a false
    positive on text that reads benign without it.

    Returns (carrier, full entry text, confidence) for each offender.
    """
    import json
    import re

    import numpy as np
    from sklearn.metrics.pairwise import cosine_similarity

    from pif.detection import semantic
    from pif.models import settings

    block_threshold = threshold if threshold is not None else settings.block_threshold

    def _load(name: str) -> list[str]:
        with open(corpus_path / name) as f:
            return [json.loads(line)["text"] for line in f if line.strip()]

    injections = _load("injections.jsonl")
    benign = _load("benign.jsonl")

    carriers: dict[int, str] = {}
    for i, text in enumerate(injections):
        match = re.match(r"^[^.?!]{3,60}[.?!]", text)
        # A carrier only matters if the entry has more after it.
        if match and len(match.group(0)) < len(text.strip()):
            carriers[i] = match.group(0)

    if not carriers:
        return []

    model = semantic._get_model()
    idx = list(carriers)
    car_embs = np.asarray(model.encode([carriers[i] for i in idx], normalize_embeddings=True))
    inj_embs = np.asarray(model.encode(injections, normalize_embeddings=True))
    ben_embs = np.asarray(model.encode(benign, normalize_embeddings=True))

    car_to_inj = cosine_similarity(car_embs, inj_embs)
    ben_max = cosine_similarity(car_embs, ben_embs).max(axis=1)

    suspects = []
    for row, i in enumerate(idx):
        sims = car_to_inj[row]
        with_entry = float(sims.max())
        without = float(np.delete(sims, i).max())
        # Same benign discount the semantic layer applies.
        score = with_entry * 0.5 if ben_max[row] > with_entry else with_entry
        score_without = without * 0.5 if ben_max[row] > without else without
        # Two conditions: this entry alone pushes the carrier over the line, and
        # the carrier reads benign once it's gone. The first alone flags every
        # attack whose opening line is the attack; the second alone flags healthy
        # entries that merely have a benign neighbour.
        if score >= block_threshold > score_without and ben_max[row] > without:
            suspects.append((carriers[i], injections[i], round(score, 4)))

    return sorted(suspects, key=lambda s: s[2], reverse=True)


@app.command()
def check_corpus(
    semantic_lint: bool = typer.Option(
        False,
        "--semantic-lint",
        help="Also flag injection entries that sit closer to the benign corpus "
        "than to the rest of the attack corpus (slow — loads the model).",
    ),
) -> None:
    """Validate and count corpus examples."""
    import json
    from pathlib import Path

    from pif.models import settings

    path = Path(settings.corpus_path)
    for fname in ("injections.jsonl", "benign.jsonl"):
        fpath = path / fname
        if not fpath.exists():
            console.print(f"[red]Missing: {fpath}[/red]")
            continue
        count = 0
        errors = 0
        with open(fpath) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                    count += 1
                except json.JSONDecodeError:
                    console.print(f"[red]{fname}:{i} invalid JSON[/red]")
                    errors += 1
        status = "[green]ok[/green]" if not errors else "[red]errors[/red]"
        console.print(f"{fname}: {count} examples — {status}")

    if not semantic_lint:
        return

    console.print("\n[yellow]Semantic lint (loading model)...[/yellow]")
    suspects = _find_carrier_text_entries(path)

    if not suspects:
        console.print("[green]No carrier text blocks on its own.[/green]")
        return

    console.print(
        f"[red]{len(suspects)} injection entries whose opening sentence blocks alone.[/red]\n"
        "[dim]These teach the index to flag whatever benign text they wrap.[/dim]"
    )
    for carrier, text, confidence in suspects:
        console.print(f"  {confidence:.3f} :: {carrier}")
        console.print(f"        [dim]in: {text[:70]}[/dim]")


@app.command()
def reindex() -> None:
    """
    Rebuild the semantic embedding index and report its size and build time.

    The index lives in module globals, not on disk, so this rebuild dies with the CLI
    process. A running server rebuilds its own on first request either way. Use this to
    check that corpus edits load cleanly and to see what they cost, not to publish an
    index for something else to pick up.
    """
    import time
    from pathlib import Path

    from pif.detection import semantic
    from pif.models import settings

    path = Path(settings.corpus_path)
    if not (path / "injections.jsonl").exists():
        console.print(f"[red]Corpus not found at {path}[/red]")
        raise typer.Exit(1)

    console.print("[yellow]Clearing existing index...[/yellow]")
    semantic.reset_corpus()

    console.print("[yellow]Loading model and rebuilding index (this may take 30s)...[/yellow]")
    t0 = time.perf_counter()
    inj_embs, benign_embs = semantic._load_corpus(settings.corpus_path)
    elapsed = time.perf_counter() - t0

    console.print(
        f"[green]Done in {elapsed:.1f}s — "
        f"{len(inj_embs)} injection embeddings, "
        f"{len(benign_embs)} benign embeddings[/green]"
    )
    console.print(
        "[dim]Index is in-memory only — a running server rebuilds its own on startup.[/dim]"
    )


@app.command()
def logs(limit: int = typer.Option(20, help="Number of recent events to show")) -> None:
    """Print recent attack events."""
    from pif import db

    async def _run() -> None:
        await db.init_db()
        events = await db.get_events(limit=limit)
        if not events:
            console.print("[dim]No events logged yet.[/dim]")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=20)
        table.add_column("Type", width=22)
        table.add_column("Confidence", width=10)
        table.add_column("Blocked", width=8)
        table.add_column("Layer", width=6)

        for e in events:
            blocked_str = "[red]YES[/red]" if e.blocked else "[green]no[/green]"
            table.add_row(
                e.timestamp[:19],
                e.attack_type.value,
                f"{e.confidence:.2f}",
                blocked_str,
                str(e.layer_triggered),
            )

        console.print(table)

    asyncio.run(_run())


@app.command()
def test(
    prompt: str | None = typer.Argument(None, help="Prompt to test. Reads from stdin if omitted."),
    threshold: float | None = typer.Option(None, help="Override block threshold for this call."),
    explain: bool = typer.Option(
        False, "--explain", help="Show each layer's verdict, not just the combined one."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON."),
) -> None:
    """Run the detection engine against a prompt."""
    import sys

    from pif.detection import engine, heuristics

    if prompt is None:
        if sys.stdin.isatty():
            console.print("[red]Error: provide a PROMPT argument or pipe text via stdin.[/red]")
            raise typer.Exit(1)
        prompt = sys.stdin.read()

    prompt = prompt.strip()
    if not prompt:
        console.print("[red]Error: empty prompt.[/red]")
        raise typer.Exit(1)

    if not json_output:
        console.print("[dim]Running detection (first run may be slow — model loading)...[/dim]")

    messages = [{"role": "user", "content": prompt}]
    result = asyncio.run(engine.analyze(messages, threshold=threshold))

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return

    verdict = (
        typer.style("BLOCKED", fg=typer.colors.RED, bold=True)
        if result.is_injection
        else typer.style("ALLOWED", fg=typer.colors.GREEN, bold=True)
    )
    patterns = ", ".join(result.matched_patterns) if result.matched_patterns else "none"

    typer.echo(f"Result:           {verdict}")
    typer.echo(f"Confidence:       {result.confidence:.4f}")
    typer.echo(f"Attack type:      {result.attack_type.value}")
    typer.echo(f"Layer triggered:  {result.layer_triggered}")
    typer.echo(f"Matched patterns: {patterns}")
    typer.echo(f"Latency:          {result.latency_ms}ms")

    if not explain:
        return

    # Re-run each layer on its own. The combined result hides which layer actually
    # decided, and when tuning the corpus that's the only thing you want to know.
    from pif.detection import semantic

    analyzed = heuristics.extract_text_from_messages(messages)
    h = heuristics.check(analyzed)

    typer.echo("\nPer-layer breakdown:")
    typer.echo(
        f"  L1 heuristics: {h.confidence:.4f} "
        f"({', '.join(h.matched_patterns) if h.matched_patterns else 'no patterns'})"
    )

    if h.confidence >= engine._HEURISTIC_FAST_PATH:
        typer.echo("  L2 semantic:   skipped — heuristics hit the fast path")
    else:
        s = semantic.check(heuristics.decode_base64_blobs(analyzed))
        typer.echo(f"  L2 semantic:   {s.confidence:.4f} (nearest {s.attack_type.value})")

    if analyzed != prompt:
        typer.echo(f"\n[dim]Text actually scored:[/dim] {analyzed[:200]!r}")


@app.command()
def eval(
    threshold: float = typer.Option(
        None, help="Block threshold (default: settings.block_threshold)"
    ),
    test_ratio: float = typer.Option(0.2, help="Fraction of corpus held out for testing"),
    seed: int = typer.Option(42, help="Random seed for split"),
    sweep: bool = typer.Option(False, "--sweep", help="Sweep thresholds 0.30–0.95"),
    save_baseline: bool = typer.Option(
        False, "--save-baseline", help="Save result as tests/eval_baseline.json"
    ),
    compare_baseline: bool = typer.Option(
        False, "--compare-baseline", help="Fail if F1 regresses vs baseline"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """Run the detection eval harness against the corpus."""
    from pif import eval as _eval
    from pif.models import settings as _settings

    exit_code = asyncio.run(
        _eval._main(
            threshold=threshold if threshold is not None else _settings.block_threshold,
            test_ratio=test_ratio,
            seed=seed,
            do_sweep=sweep,
            save_baseline_flag=save_baseline,
            compare_baseline_flag=compare_baseline,
            json_output=json_output,
        )
    )
    raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
