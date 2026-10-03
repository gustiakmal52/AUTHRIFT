from rich.console import Console

console = Console(stderr=True)


def banner() -> None:
    console.print("AUTHRIFT v0.1.0", style="bold cyan")
    console.print("API Authorization Differential Tester", style="dim")
    console.print()


def info(msg: str) -> None:
    console.print(f"  {msg}")


def success(msg: str) -> None:
    console.print(f"  [green]✓[/green] {msg}")


def warning(msg: str) -> None:
    console.print(f"  [yellow]![/yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"  [red]✗[/red] {msg}")


def finding_alert(finding_id: str, endpoint: str, confidence: str) -> None:
    console.print(f"  [red bold]POSSIBLE AUTHORIZATION ISSUE[/red bold] {finding_id}")
    console.print(f"    {endpoint}")
    console.print(f"    Confidence: {confidence}")
    console.print()
