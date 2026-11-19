"""Command-line interface for safeharbor-check.

Subcommands:
  safeharbor-check check FILE [--report FILE] [--delimiter CHAR]
      Audit a CSV against the Safe Harbor identifier classes
      (45 CFR 164.514(b)(2)) and print a per-class report.
      Exit codes: 0 = no mechanical violations and nothing left
      unverified except the always-unverifiable items noted in the
      report; 1 = violations found; 3 = no violations, but some
      columns cannot be verified mechanically.

  safeharbor-check apply FILE --out FILE [--log FILE]
                         [--delimiter CHAR]
                         [--dates COL,...] [--zips COL,...]
                         [--ages COL,...] [--drop COL,...]
      Apply the mechanical fixes, but ONLY to declared columns:
      dates -> year, ZIP -> first three digits or 000, ages over
      89 -> "90+", declared identifier columns dropped. Undeclared
      columns are copied through unchanged.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import core
from .core import SafeHarborError


def _split(value):
    if not value:
        return ()
    return tuple(v.strip() for v in value.split(",") if v.strip())


def build_parser():
    parser = argparse.ArgumentParser(
        prog="safeharbor-check",
        description="Check a structured CSV against the HIPAA Safe "
                    "Harbor identifier classes (45 CFR 164.514(b)(2)) "
                    "-- a checker only; it certifies nothing.")
    sub = parser.add_subparsers(dest="command")

    chk = sub.add_parser(
        "check", help="audit a CSV and print a per-class report")
    chk.add_argument("file", help="input CSV")
    chk.add_argument("--report", default=None,
                     help="also write the report to this file")

    app = sub.add_parser(
        "apply", help="apply the mechanical fixes to declared columns only")
    app.add_argument("file", help="input CSV")
    app.add_argument("--out", required=True, help="output CSV")
    app.add_argument("--log", default=None,
                     help="transform log file (default: <out>.log.txt)")
    app.add_argument("--dates", default=None,
                     help="comma-separated date columns -> keep year only")
    app.add_argument("--zips", default=None,
                     help="comma-separated ZIP columns -> first three "
                          "digits, or 000 for restricted prefixes")
    app.add_argument("--ages", default=None,
                     help="comma-separated age columns -> '90+' above 89")
    app.add_argument("--drop", default=None,
                     help="comma-separated identifier columns to drop")
    for command in (chk, app):
        command.add_argument(
            "--delimiter", default=None, metavar="CHAR",
            help=r"declared field separator (default: comma); use \t for tab")
    return parser


def cmd_check(args):
    fieldnames, rows = core.read_csv(args.file, delimiter=args.delimiter or ",")
    result = core.check_data(fieldnames, rows)
    report = core.format_report(result, args.file, delimiter=args.delimiter)
    print(report, end="")
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"report written to {args.report}", file=sys.stderr)
    return result.exit_code


def cmd_apply(args):
    fieldnames, rows = core.read_csv(args.file, delimiter=args.delimiter or ",")
    result = core.apply_data(
        fieldnames, rows,
        date_cols=_split(args.dates), zip_cols=_split(args.zips),
        age_cols=_split(args.ages), drop_cols=_split(args.drop))
    core.write_csv(args.out, result.fieldnames, result.rows,
                   delimiter=args.delimiter or ",")
    if args.delimiter is not None:
        result.log_lines.insert(1, f"delimiter    : {args.delimiter!a}")
    log_text = "\n".join(result.log_lines) + "\n"
    log_path = args.log or (str(args.out) + ".log.txt")
    Path(log_path).write_text(log_text, encoding="utf-8")
    print(f"wrote {args.out} ({len(result.rows)} rows, "
          f"{len(result.fieldnames)} columns)")
    print(f"transform log: {log_path}")
    print("Note: only declared columns were changed. This run certifies "
          "nothing --")
    print("see the residual-risk note in the log.")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        if args.delimiter is not None:
            delimiter = "\t" if args.delimiter == r"\t" else args.delimiter
            args.delimiter = core.validate_delimiter(delimiter)
        if args.command == "check":
            return cmd_check(args)
        if args.command == "apply":
            return cmd_apply(args)
    except SafeHarborError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
