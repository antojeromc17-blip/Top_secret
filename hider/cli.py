"""
CLI entry point for HIDER.

Commands
────────
  hider hide <folder>         Hide a folder.  Prompts for passphrase on first run only.
  hider unhide [text]         Restore hidden vaults (optionally filtered by folder name).
  hider list                  List all hidden vaults (requires passphrase).
  hider recover               Scan vault roots and restore; works without state dir.
  hider change-passphrase     Re-encrypt private key with a new passphrase.
"""
from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="hider",
    help="File vault — hide folders so they leave no visible trace.",
    add_completion=False,
)

MAX_ATTEMPTS = 5


def _prompt_passphrase(prompt: str = "Passphrase") -> str:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            pw = getpass.getpass(f"{prompt}: ")
        except (EOFError, KeyboardInterrupt):
            raise typer.Abort()
        if pw:
            return pw
        remaining = MAX_ATTEMPTS - attempt
        if remaining:
            print(f"Passphrase cannot be empty.  {remaining} attempt(s) left.")
    raise typer.Exit(1)


def _prompt_passphrase_confirm() -> str:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        pw1 = getpass.getpass("New passphrase: ")
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw1 == pw2 and pw1:
            return pw1
        if pw1 != pw2:
            print("Passphrases do not match.  Try again.")
        else:
            print("Passphrase cannot be empty.")
    raise typer.Exit(1)


# ── hide ──────────────────────────────────────────────────────────────────────

@app.command()
def hide(
    folder: Path = typer.Argument(..., help="Folder to hide."),
) -> None:
    """Hide a folder so it leaves no visible trace."""
    from .preflight import PreflightError
    from .vault     import hide as _hide

    if not folder.exists():
        typer.echo(f"Error: '{folder}' does not exist.", err=True)
        raise typer.Exit(1)
    if not folder.is_dir():
        typer.echo(f"Error: '{folder}' is not a folder.", err=True)
        raise typer.Exit(1)

    def _passphrase_fn() -> str:
        typer.echo("First use: set a passphrase to protect your vaults.")
        pw = _prompt_passphrase_confirm()
        from .state import add_to_user_path
        add_to_user_path()
        return pw

    try:
        _hide(folder, _passphrase_fn)
        typer.echo("Done. Folder locked and hidden.")
    except PreflightError as exc:
        typer.echo(f"Cannot hide: {exc}", err=True)
        raise typer.Exit(1)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


# ── unhide ────────────────────────────────────────────────────────────────────

@app.command()
def unhide(
    text: Optional[str] = typer.Argument(None, help="Filter by folder name (substring)."),
) -> None:
    """Restore hidden vaults (all, or those matching a folder-name filter)."""
    from .state import has_keypair
    from .vault import unhide as _unhide

    if not has_keypair():
        typer.echo("No hidden vaults found (no key material in state dir).", err=True)
        raise typer.Exit(1)

    passphrase = _prompt_passphrase()
    try:
        count = _unhide(passphrase, text_filter=text)
        if count == 0:
            typer.echo("Nothing to restore.")
        else:
            typer.echo(f"Done. Restored {count} vault(s).")
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


# ── list ──────────────────────────────────────────────────────────────────────

@app.command(name="list")
def list_cmd() -> None:
    """List all hidden vaults (requires passphrase)."""
    from .state import has_keypair
    from .vault import list_vaults_cmd

    if not has_keypair():
        typer.echo("No hidden vaults found.", err=True)
        raise typer.Exit(1)

    passphrase = _prompt_passphrase()
    try:
        list_vaults_cmd(passphrase)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


# ── recover ───────────────────────────────────────────────────────────────────

@app.command()
def recover() -> None:
    """
    Scan vault roots for hidden folders and restore them.
    Works even if the state directory has been deleted.
    """
    from .vault import recover_cmd

    passphrase = _prompt_passphrase()
    try:
        recover_cmd(passphrase)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


# ── change-passphrase ─────────────────────────────────────────────────────────

@app.command(name="change-passphrase")
def change_passphrase() -> None:
    """Re-encrypt the private key and update all vault manifests with a new passphrase."""
    from .state import has_keypair
    from .vault import change_passphrase as _change_pp

    if not has_keypair():
        typer.echo("No key material found. Run 'hider hide <folder>' first.", err=True)
        raise typer.Exit(1)

    old_pw = _prompt_passphrase("Current passphrase")
    new_pw = _prompt_passphrase_confirm()
    try:
        _change_pp(old_pw, new_pw)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

