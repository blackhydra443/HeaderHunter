#!/usr/bin/env python3

import requests
import argparse
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps to prevent XSS attacks.",
    "X-Frame-Options": "Prevents clickjacking.",
    "Strict-Transport-Security": "Enforces HTTPS.",
    "X-Content-Type-Options": "Prevents MIME-sniffing.",
    "Referrer-Policy": "Controls referrer info sent.",
    "Permissions-Policy": "Limits browser features.",
    "X-XSS-Protection": "Basic protection against reflected XSS."
}

def scan_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        table = Table(title=f"Security Headers for {url}")
        table.add_column("Header", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Description", style="magenta")

        for header, desc in SECURITY_HEADERS.items():
            if header in headers:
                table.add_row(header, "[bold green]✔ Present[/]", desc)
            else:
                table.add_row(header, "[bold red]✘ Missing[/]", desc)

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a website for missing security headers.")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    if not args.url.startswith("http"):
        args.url = "https://" + args.url

    scan_headers(args.url)
