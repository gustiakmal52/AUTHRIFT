from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from authrift.utils.logging import console, banner, info, success, warning, error

app = typer.Typer(
    name="authrift",
    help="AUTHRIFT — API Authorization Differential Tester",
    no_args_is_help=True,
)


@app.command("import")
def import_requests(
    file: Path = typer.Argument(..., help="Path to request file (raw HTTP, cURL, or HAR)"),
):
    """Import and inspect requests from a file."""
    banner()

    if not file.exists():
        error(f"File not found: {file}")
        raise typer.Exit(1)

    suffix = file.suffix.lower()

    if suffix in (".har", ".json"):
        from authrift.parser.har import parse_har
        requests = parse_har(file)
    else:
        from authrift.parser.raw_http import parse_request_file
        requests = parse_request_file(file)

    from authrift.detection.identifiers import detect_identifiers

    info(f"Loaded {len(requests)} request(s) from {file.name}")
    console.print()

    table = Table(show_header=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Method", width=8)
    table.add_column("Path")
    table.add_column("IDs Found", width=10)

    total_ids = 0
    for i, req in enumerate(requests, 1):
        ids = detect_identifiers(req)
        total_ids += len(ids)
        table.add_row(str(i), req.method.value, req.path, str(len(ids)))

    console.print(table)
    console.print()
    info(f"{len(requests)} requests, {total_ids} potential object identifiers")


@app.command("test")
def test_requests(
    file: Path = typer.Argument(..., help="Path to request file"),
    actors: Path = typer.Option(..., "--actors", "-a", help="Path to actors YAML config"),
    actor_a: str = typer.Option("user_a", "--actor-a", help="Name of baseline actor"),
    actor_b: str = typer.Option("user_b", "--actor-b", help="Name of test actor"),
    admin: Optional[str] = typer.Option(None, "--admin", help="Name of admin actor"),
    allow_state_changing: bool = typer.Option(False, "--allow-state-changing", help="Allow POST/PUT/PATCH/DELETE"),
    max_requests: int = typer.Option(100, "--max-requests", help="Maximum requests to test"),
    delay: int = typer.Option(0, "--delay", help="Delay between mutations in ms"),
    rate_limit: float = typer.Option(10.0, "--rate-limit", help="Maximum requests per second (RPS)"),
    timeout: float = typer.Option(30.0, "--timeout", help="Request timeout in seconds"),
    include_raw_evidence: bool = typer.Option(False, "--include-raw-evidence", help="Store unredacted raw evidence in reports"),
    report_dir: str = typer.Option("reports", "--report-dir", help="Output directory for reports"),
):
    """Run authorization differential tests."""
    banner()

    if not file.exists():
        error(f"File not found: {file}")
        raise typer.Exit(1)

    if not actors.exists():
        error(f"Actors config not found: {actors}")
        raise typer.Exit(1)

    from authrift.config import load_actors, load_scan_config
    from authrift.parser.raw_http import parse_request_file
    from authrift.parser.har import parse_har
    from authrift.engine.runner import run_scan
    from authrift.reporting.markdown import write_reports
    from authrift.reporting.json_report import write_json_report
    from authrift.detection.authorization import reset_counter

    reset_counter()

    actors_dict = load_actors(actors)
    if actor_a not in actors_dict:
        error(f"Actor '{actor_a}' not found in {actors}")
        raise typer.Exit(1)
    if actor_b not in actors_dict:
        error(f"Actor '{actor_b}' not found in {actors}")
        raise typer.Exit(1)

    admin_actor = actors_dict.get(admin) if admin else None

    suffix = file.suffix.lower()
    if suffix in (".har", ".json"):
        requests = parse_har(file)
    else:
        requests = parse_request_file(file)

    config = load_scan_config(
        {
            "allow_state_changing": allow_state_changing,
            "max_requests": max_requests,
            "delay_ms": delay,
            "rate_limit_rps": rate_limit,
            "timeout_s": timeout,
            "include_raw_evidence": include_raw_evidence,
            "report_dir": report_dir,
        },
        config_path=actors,
    )

    info(f"Loaded requests: {len(requests)}")
    info(f"Actors: {actor_a}, {actor_b}")
    if admin_actor:
        info(f"Admin actor: {admin}")
    info(f"Rate limit: {rate_limit} RPS | Delay: {delay}ms | State-changing: {allow_state_changing}")
    console.print()

    result = run_scan(requests, actors_dict[actor_a], actors_dict[actor_b], admin_actor, config)

    console.print()
    info("Completed.")
    info(f"  Imported requests processed: {result.imported_requests_processed or result.total_requests}")
    info(f"  HTTP requests sent: {result.http_requests_sent}")
    info(f"  Mutations completed: {result.mutations_completed or result.total_mutations}")
    info(f"  Potential findings: {len(result.findings)}")

    if result.findings:
        md_paths = write_reports(result, report_dir, include_raw_evidence=include_raw_evidence)
        json_path = write_json_report(result, report_dir, include_raw_evidence=include_raw_evidence)
        console.print()
        success(f"Reports written to {report_dir}/")
        for p in md_paths:
            info(f"  {p}")
        info(f"  {json_path}")
    else:
        success("No potential authorization issues detected.")


@app.command("report")
def generate_report(
    report_dir: str = typer.Option("reports", "--report-dir", help="Reports directory"),
):
    """Show summary of previous scan results."""
    banner()
    summary_path = Path(report_dir) / "summary.md"
    if not summary_path.exists():
        warning("No scan results found. Run 'authrift test' first.")
        raise typer.Exit(1)

    console.print(summary_path.read_text())


if __name__ == "__main__":
    app()
