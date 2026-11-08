# labs/lab02/main.py
import argparse
from labs.lab02.task1 import run_demo
from labs.lab02.task2 import run_ssl_monitor


def main():
    parser = argparse.ArgumentParser(description="Lab 02 CLI Utility (Variant 10 - SSL Certificate Monitor)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Команда demo (Завдання 1)
    subparsers.add_parser("demo", help="Run OOP user and session demonstration")

    # Команда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser("analyze", help="Run SSL/TLS certificate monitor")
    analyze_parser.add_argument(
        "--certs-data",
        default="labs/lab02/data/data_v10/certificates.json",
        help="Path to certificates JSON file"
    )
    analyze_parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Days threshold for expiration warning"
    )
    analyze_parser.add_argument(
        "--output-report",
        default="labs/lab02/data/ssl_expiry_report.csv",
        help="Path to save output report"
    )
    analyze_parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Report export format"
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_ssl_monitor(
            certs_path=args.certs_data,
            days_warning=args.days_warning,
            output_path=args.output_report,
            file_format=args.format
        )


if __name__ == "__main__":
    main()