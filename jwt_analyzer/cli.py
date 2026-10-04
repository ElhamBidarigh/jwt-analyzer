"""Command-line interface for the SecurAI JWT Analyzer."""
import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .analyzer import analyze, AnalysisResult
from .attacks import forge_none, brute_force_secret, forge_hs256_with_public_key
from .report import save_html

console = Console()

SEV_STYLE = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "bold blue",
    "low": "dim white",
    "info": "dim cyan",
}


def _print_result(result: AnalysisResult, verbose: bool) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold]JWT Security Analysis[/bold]\n"
        f"Algorithm: [cyan]{result.algorithm}[/cyan]\n"
        f"Score: {_score_text(result.score)}  ·  "
        f"Findings: [bold]{len(result.findings)}[/bold]",
        border_style="green",
    ))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("ID", width=14)
    table.add_column("Title")
    for f in sorted(result.findings,
                    key=lambda x: ["critical","high","medium","low","info"].index(x.severity)
                    if x.severity in ["critical","high","medium","low","info"] else 9):
        table.add_row(
            Text(f.severity.upper(), style=SEV_STYLE.get(f.severity, "")),
            f.id,
            f.title,
        )
    console.print(table)

    if verbose and result.findings:
        console.print()
        for f in result.findings:
            console.print(Panel(
                f"[bold]{f.title}[/bold]\n\n{f.description}\n\n"
                f"[green]Fix:[/green] {f.remediation}"
                + (f"\n\n[dim]{f.evidence}[/dim]" if f.evidence else ""),
                title=f"[{f.severity.upper()}] {f.id}",
                border_style=SEV_STYLE.get(f.severity, "white"),
            ))


def _score_text(score: int) -> str:
    if score >= 80:
        return f"[green]{score}/100[/green]"
    if score >= 60:
        return f"[cyan]{score}/100[/cyan]"
    if score >= 40:
        return f"[yellow]{score}/100[/yellow]"
    return f"[red]{score}/100[/red]"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwt-analyzer",
        description="Analyze a JWT for common security vulnerabilities.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument("--token", required=True,
                        help="The JWT string to analyze.")
    parser.add_argument("--wordlist", default="jwt_analyzer/wordlists/common.txt",
                        help="Wordlist for HMAC secret brute-force.")
    parser.add_argument("--public-key", default=None,
                        help="RSA/EC public key (PEM) for RS256->HS256 detection.")
    parser.add_argument("--output", default=None,
                        help="Path to save an HTML report.")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON instead of a table.")
    parser.add_argument("--verbose", action="store_true",
                        help="Show detailed explanations for each finding.")
    parser.add_argument("--forge-none", action="store_true",
                        help="Also output an alg=none forgery of the token.")
    parser.add_argument("--attack-brute", action="store_true",
                        help="Run a wordlist brute-force against the HMAC secret.")
    parser.add_argument("--attack-confusion", action="store_true",
                        help="Run RS256->HS256 confusion (requires --public-key).")

    args = parser.parse_args(argv)

    try:
        result = analyze(args.token)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 2

    # ── Optional active attacks ───────────────────────────────────
    attack_output = {}

    if args.forge_none:
        try:
            attack_output["alg_none_token"] = forge_none(args.token)
        except Exception as exc:
            attack_output["alg_none_error"] = str(exc)

    if args.attack_brute:
        try:
            secret = brute_force_secret(args.token, args.wordlist)
            attack_output["brute_secret"] = secret if secret else "(not found)"
        except Exception as exc:
            attack_output["brute_error"] = str(exc)

    if args.attack_confusion:
        if not args.public_key:
            attack_output["confusion_error"] = "--public-key is required"
        else:
            try:
                attack_output["confusion_token"] = forge_hs256_with_public_key(
                    args.token, args.public_key
                )
            except Exception as exc:
                attack_output["confusion_error"] = str(exc)

    # ── Output ────────────────────────────────────────────────────
    if args.json:
        payload = {
            "algorithm": result.algorithm,
            "score": result.score,
            "header": result.header,
            "payload": result.payload,
            "findings": [f.__dict__ for f in result.findings],
            "attacks": attack_output,
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        _print_result(result, args.verbose)
        if attack_output:
            console.print()
            console.print(Panel(
                "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in attack_output.items()),
                title="[red]Active Attacks[/red]",
                border_style="red",
            ))

    if args.output:
        path = save_html(result, args.output)
        console.print(f"\n[green]HTML report saved to:[/green] {path}")

    # Exit 1 if any critical/high finding (useful for CI)
    if any(f.severity in ("critical", "high") for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
