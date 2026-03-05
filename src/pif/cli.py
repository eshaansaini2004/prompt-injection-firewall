"""
CLI entrypoint. `pif start`, `pif reindex`, `pif logs`.
"""
from __future__ import annotations

import asyncio

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


@app.command()
def check_corpus() -> None:
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


if __name__ == "__main__":
    app()
