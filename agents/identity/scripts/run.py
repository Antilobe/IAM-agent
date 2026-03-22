#!/usr/bin/env python3
"""CLI entry point for the Identity Security Agent."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv

# Load .env from agent directory
load_dotenv(Path(__file__).parent.parent / ".env")

import typer
from rich.console import Console

# Ensure the src dir is on the path when running as a script
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from identity_agent.agent import IdentityAgent
from identity_agent.config import load_config

app = typer.Typer(help="Identity Security Agent — Entra ID posture assessment")
console = Console()


@app.command()
def assess(
    tenant_id: str = typer.Option(None, help="Azure tenant ID (overrides config)"),
    config_path: str = typer.Option(None, help="Path to config YAML"),
) -> None:
    """Run a full identity assessment."""
    cfg = load_config(Path(config_path) if config_path else None)
    if tenant_id:
        cfg.tenant_id = tenant_id

    if not cfg.tenant_id:
        console.print("[red]Error:[/red] tenant_id is required (set AZURE_TENANT_ID or --tenant-id)")
        raise typer.Exit(1)

    console.print(f"Starting identity assessment for tenant [bold]{cfg.tenant_id}[/bold]")
    agent = IdentityAgent(cfg)
    result = asyncio.run(agent.run())
    console.print_json(data=result)


if __name__ == "__main__":
    app()
