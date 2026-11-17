"""Core logic for safeharbor-check.

This tool is a CHECKER for structured CSVs against the identifier
classes listed in the HIPAA Safe Harbor rule, 45 CFR 164.514(b)(2).
It is not a certifying tool: several classes cannot be verified by any
mechanical scan of a CSV, and every report this module produces says so.

Two operations:

  check -- audit a CSV, class by class (A)-(R), and report concrete
           mechanical violations, plus everything that cannot be
           verified mechanically.
  apply -- transform ONLY the columns the user declares, with one of
           the mechanical fixes the rule itself specifies:
           dates -> year only, ZIP codes -> first three digits (or 000
           for low-population prefixes), ages over 89 -> "90+", and
           dropping columns the user declares as identifier columns.
           Undeclared columns are copied through unchanged.

Standard library only.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Wording that must appear in every report and every transform log.
# ---------------------------------------------------------------------------

RESIDUAL_RISK_NOTE = (
    "RESIDUAL RISK -- READ THIS:\n"
    "  * Free-text columns cannot be verified by this tool. A person can\n"
    "    type a name, a date, or any other identifier into a notes field,\n"
    "    and no pattern scan can prove they did not. Free-text columns\n"
    "    are always reported as CANNOT VERIFY -- manual review required,\n"
    "    and are never reported as passing.\n"
    "  * Class (R) -- any other unique identifying number, characteristic\n"
    "    or code -- cannot be verified mechanically. Only a human who\n"
    "    knows the data can judge it.\n"
    "  * The Safe Harbor rule also requires that the holder of the data\n"
    "    has no actual knowledge that the remaining information could be\n"
    "    used to identify a person. Actual knowledge is not in the file,\n"
    "    so no tool can check it.\n"
    "  * A report with no violations found means only: none of the\n"
    "    mechanical checks this tool can perform found a problem. It\n"
    "    does not certify that a file meets HIPAA requirements, and it\n"
    "    is not a legal determination of any kind."
)

ZIP_LIST_WARNING = (
    "ZIP LIST LIMIT: the bundled restricted-prefix list is the list "
    "published by the U.S. Department of Health and Human Services "
    "(guidance dated November 26, 2012), derived from Bureau of the "
    "Census 2000 Census ZIP Code Tabulation Areas. HHS warns in that "
    "guidance not to rely on the list if more current Census data is "
    "available, and no complete updated restricted list based on a "
    "later census was found published as of 2026-11-17. A ZIP prefix "
    "that is NOT in the bundled list is therefore reported as 'not "
    "flagged by the bundled 2000-Census list -- not verified against "
    "current Census data', never as verified safe."
)


class SafeHarborError(Exception):
    """A clean, user-facing error (never a traceback)."""


# ---------------------------------------------------------------------------
# The bundled ZIP data
# ---------------------------------------------------------------------------

def load_restricted_zip3():
    """Return (frozenset_of_prefixes, source_description)."""
    path = Path(__file__).resolve().parent / "data" / "zip3_restricted_hhs.csv"
    prefixes = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "zip3":
            continue
        prefixes.append(line)
    if len(prefixes) != 17:
        raise SafeHarborError(
            f"bundled ZIP data looks wrong: expected the 17 HHS-published "
            f"restricted prefixes, found {len(prefixes)} in {path}")
    return frozenset(prefixes), (
        "HHS guidance, November 26, 2012 (2000 Census ZCTAs; "
        "67 FR 53182, 53233-53234)")


# ---------------------------------------------------------------------------
# Patterns and column-name hints
# ---------------------------------------------------------------------------

RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
RE_PHONE = re.compile(
    r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]\d{3}[-.\s]\d{4}\b")
RE_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 is validated with the ipaddress module (see _has_ipv6), not a
# regex: loose colon-patterns also match times and MAC-like strings.
RE_ZIP5 = re.compile(r"^\d{5}(?:-\d{4})?$")
RE_ZIP3 = re.compile(r"^\d{3}$")
RE_YEAR = re.compile(r"^(?:19|20)\d{2}$")
# Dates carrying more than a year: ISO, US, and written forms.
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?"
RE_DATE_PRECISE = re.compile(
    r"(?:\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?)"  # 2021-03-04, ISO date-time
    r"|(?:\b\d{4}/\d{2}/\d{2}\b)"         # 2021/03/04
    r"|(?:\b\d{4}-\d{2}\b)"               # 2021-03 (year + month)
    r"|(?:\b\d{1,2}/\d{1,2}/\d{2,4}\b)"   # 3/4/2021
    r"|(?:\b\d{1,2}-\d{1,2}-\d{2,4}\b)"   # 3-4-2021
    r"|(?:\b\d{1,2}\.\d{1,2}\.(?:19|20)\d{2}\b)"  # 4.3.2021 / 03.04.2021
    r"|(?:\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\b)"  # 20210304
    r"|(?:\b" + _MONTH + r"\s+\d{1,2},?\s+\d{4}\b)"   # March 4, 2021
    r"|(?:\b\d{1,2}\s+" + _MONTH + r"\s+\d{4}\b)"     # 4 Mar 2021
    r"|(?:\b" + _MONTH + r"\s+\d{4}\b)", re.IGNORECASE)  # March 2021

FREE_TEXT_HINTS = (
    "note", "comment", "narrative", "free_text", "freetext", "remark",
    "description", "history_text", "clinician_note", "note_text",
    "summary", "observation", "detail", "history", "memo", "annotation",
    "reason",
)

# Column-name hints per class letter. Matching is on the normalised name
# (lowercase, non-alphanumerics collapsed to underscores).
NAME_HINTS = {
    "A": ("name", "patient_name", "first_name", "last_name", "full_name",
          "middle_name", "maiden"),
    "B": ("address", "street", "city", "county", "precinct", "zip",
          "postal", "geocode", "latitude", "longitude", "lat", "lon",
          "lng"),
    "C": ("date", "dob", "birth", "admission", "discharge", "visit_date",
          "age"),
    "D": ("phone", "telephone", "mobile", "cell_phone"),
    "E": ("fax",),
    "F": ("email", "e_mail"),
    "G": ("ssn", "social_security"),
    "H": ("mrn", "medical_record", "med_record"),
    "I": ("health_plan", "beneficiary", "insurance_id", "member_id",
          "policy_number"),
    "J": ("account", "acct"),
    "K": ("certificate", "license", "licence"),
    "L": ("vehicle", "vin", "plate"),
    "M": ("device", "serial"),
    "N": ("url", "website", "web_address"),
    "O": ("ip_address", "ip_addr"),
    "P": ("biometric", "fingerprint", "voiceprint"),
    "Q": ("photo", "photograph", "image_file", "face"),
}

CLASSES = [
    ("A", "Names"),
    ("B", "Geographic subdivisions smaller than a state "
          "(address, city, county, ZIP, geocodes)"),
    ("C", "Dates (all elements except year) and ages over 89"),
    ("D", "Telephone numbers"),
    ("E", "Fax numbers"),
    ("F", "Email addresses"),
    ("G", "Social Security numbers"),
    ("H", "Medical record numbers"),
    ("I", "Health plan beneficiary numbers"),
    ("J", "Account numbers"),
    ("K", "Certificate / license numbers"),
    ("L", "Vehicle identifiers and license plate numbers"),
    ("M", "Device identifiers and serial numbers"),
    ("N", "Web URLs"),
    ("O", "IP addresses"),
    ("P", "Biometric identifiers"),
    ("Q", "Full-face photographs and comparable images"),
    ("R", "Any other unique identifying number, characteristic, or code"),
]

# How each class can be checked in a structured CSV:
#   "values"  -- presence by column name AND value patterns / value rules
#   "name"    -- presence by column name only; the values themselves
#                (a number is a number) cannot be told apart mechanically
#   "never"   -- cannot be verified mechanically at all
CHECKABILITY = {
    "A": "name", "B": "values", "C": "values", "D": "values",
    "E": "name", "F": "values", "G": "values", "H": "name",
    "I": "name", "J": "name", "K": "name", "L": "name", "M": "name",
    "N": "values", "O": "values", "P": "name", "Q": "name",
    "R": "never",
}

CHECKABILITY_TEXT = {
    "values": "checked by column name and by value patterns/rules",
    "name": "checked by column name only -- values cannot be told apart "
            "mechanically",
    "never": "cannot be verified mechanically",
}


def _norm(name):
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _hint_class(col_norm):
    # More specific classes win over the generic geography hints:
    # "email_address" is class (F), not (B); "ip_address" is (O), not (B).
    priority = ("G", "F", "D", "E", "O", "N", "H", "I", "J", "K", "L",
                "M", "P", "Q", "A", "C", "B")
    for letter in priority:
        for hint in NAME_HINTS[letter]:
            if col_norm == hint or col_norm.startswith(hint + "_") \
                    or col_norm.endswith("_" + hint) \
                    or ("_" + hint + "_") in ("_" + col_norm + "_"):
                return letter
    return None


def _is_age_col(col_norm):
    return col_norm == "age" or col_norm.endswith("_age") \
        or col_norm.startswith("age_") \
        or col_norm == "years_old" or col_norm.endswith("_years_old") \
        or col_norm == "yrs_old" or col_norm.endswith("_yrs_old")


def _is_age_aggregate(value):
    """True for the '90 or older' aggregate, tolerating spacing/case."""
    return re.sub(r"\s+", "", value.lower()) in ("90+", "90orolder", ">=90")


def _is_birth_col(col_norm):
    return "birth" in col_norm or "dob" in col_norm


def _has_ipv6(value):
    """True if any whitespace/comma-separated token is a valid IPv6
    address. Validated with the ipaddress module (not a loose regex),
    so times like 10:20:30 and MAC-like strings do not match."""
    for tok in re.split(r"[\s,;]+", value):
        tok = tok.strip("[]()<>\"'")
        if ":" in tok:
            try:
                ipaddress.IPv6Address(tok)
                return True
            except ValueError:
                continue
    return False


def _is_zip_col(col_norm):
    return "zip" in col_norm or "postal" in col_norm


def _is_state_col(col_norm):
    return col_norm in ("state", "state_code", "us_state")


# ---------------------------------------------------------------------------
# CSV reading
# ---------------------------------------------------------------------------

def read_csv(path):
    p = Path(path)
    if not p.is_file():
        raise SafeHarborError(f"input file not found: {path}")
    if p.stat().st_size == 0:
        raise SafeHarborError(f"input file is empty: {path}")
    try:
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SafeHarborError(f"{path} is not UTF-8 text: {exc}")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise SafeHarborError(f"{path} has no header row.")
    seen, dupes = set(), []
    for name in reader.fieldnames:
        if name in seen and name not in dupes:
            dupes.append(name)
        seen.add(name)
    if dupes:
        raise SafeHarborError(
            f"{path} has duplicate column name(s): {', '.join(dupes)}. "
            f"With duplicate headers only one of the columns can be "
            f"read, so the others would escape every check -- rename "
            f"the columns so each name is unique.")
    rows = list(reader)
    if not rows:
        raise SafeHarborError(f"{path} contains no data rows.")
    return reader.fieldnames, rows


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    letter: str
    column: str
    status: str          # VIOLATION | CANNOT_VERIFY | OK
    detail: str


@dataclass
class CheckResult:
    findings: list = field(default_factory=list)
    rows: int = 0
    columns: list = field(default_factory=list)

    @property
    def violations(self):
        return [f for f in self.findings if f.status == "VIOLATION"]

    @property
    def unverified(self):
        # The whole-file class (R) note is a standing residual-risk item,
        # present for every file; it is reported loudly but does not by
        # itself change the exit code. Column-level CANNOT_VERIFY items
        # (free text, unverified ZIP prefixes) do.
        return [f for f in self.findings
                if f.status == "CANNOT_VERIFY"
                and f.column != "(whole file)"]

    @property
    def exit_code(self):
        if self.violations:
            return 1
        if self.unverified:
            return 3
        return 0


def _values(rows, col):
    return [str(r.get(col) or "").strip() for r in rows]


def _first_hits(values, regex, limit=3):
    hits = [v for v in values if v and regex.search(v)]
    return hits[:limit], len(hits)


def check_data(fieldnames, rows):
    restricted, _src = load_restricted_zip3()
    result = CheckResult(rows=len(rows), columns=list(fieldnames))
    add = result.findings.append

    for col in fieldnames:
        norm = _norm(col)
        vals = _values(rows, col)
        nonempty = [v for v in vals if v]
        letter = _hint_class(norm)

        # --- free text: never passes -------------------------------------
        if any(h in norm for h in FREE_TEXT_HINTS):
            hits = []
            for label, rx in (("SSN-like", RE_SSN), ("email-like", RE_EMAIL),
                              ("phone-like", RE_PHONE),
                              ("URL-like", RE_URL), ("IP-like", RE_IPV4),
                              ("precise-date-like", RE_DATE_PRECISE)):
                found, n = _first_hits(nonempty, rx, limit=1)
                if found:
                    hits.append(f"{label} pattern in {n} value(s), "
                                f"e.g. {found[0]!r}")
            v6 = [v for v in nonempty if _has_ipv6(v)]
            if v6:
                hits.append(f"IPv6-like pattern in {len(v6)} value(s), "
                            f"e.g. {v6[0]!r}")
            detail = ("free-text column: cannot verify -- manual review "
                      "required")
            if hits:
                detail += "; ALSO FOUND: " + "; ".join(hits)
            add(Finding("R", col, "CANNOT_VERIFY", detail))
            continue

        # --- class C: ages ------------------------------------------------
        if _is_age_col(norm):
            bad = []
            for v in nonempty:
                if _is_age_aggregate(v):
                    continue
                try:
                    if float(v) > 89:
                        bad.append(v)
                except ValueError:
                    bad.append(f"{v!r} (not a number or the '90+' aggregate)")
            if bad:
                add(Finding("C", col, "VIOLATION",
                            f"age value(s) over 89 not aggregated to '90+': "
                            f"{bad[:3]} ({len(bad)} row(s))"))
            else:
                add(Finding("C", col, "OK",
                            "no age over 89 found; ages at/above 90 must "
                            "appear only as the '90+' aggregate"))
            continue

        # --- class B: ZIP codes -------------------------------------------
        if _is_zip_col(norm):
            five, three_restricted, three_other, weird = [], [], [], []
            for v in nonempty:
                if v == "000":
                    pass
                elif RE_ZIP5.match(v):
                    five.append(v)
                elif RE_ZIP3.match(v):
                    (three_restricted if v in restricted
                     else three_other).append(v)
                else:
                    weird.append(v)
            if five:
                add(Finding("B", col, "VIOLATION",
                            f"ZIP values longer than 3 digits: {five[:3]} "
                            f"({len(five)} row(s)); only the first three "
                            f"digits may be kept, and only under the "
                            f"population rule"))
            if three_restricted:
                add(Finding("B", col, "VIOLATION",
                            f"3-digit ZIP prefix(es) {sorted(set(three_restricted))} "
                            f"are in the bundled restricted list (combined "
                            f"population 20,000 or fewer) and must be "
                            f"changed to 000"))
            if three_other:
                add(Finding("B", col, "CANNOT_VERIFY",
                            f"3-digit ZIP prefix(es) "
                            f"{sorted(set(three_other))[:5]} are not in the "
                            f"bundled restricted list, but that list is "
                            f"from the 2000 Census -- not verified against "
                            f"current Census data"))
            if weird:
                add(Finding("B", col, "VIOLATION",
                            f"values that are not 3-digit, 5-digit or "
                            f"'000' ZIP codes: {weird[:3]}"))
            if not nonempty:
                add(Finding("B", col, "OK",
                            "column contains no values -- nothing to "
                            "check"))
            elif not (five or three_restricted or three_other or weird):
                add(Finding("B", col, "OK",
                            "all ZIP values are '000'"))
            continue

        # --- class B: other geography -------------------------------------
        if letter == "B":
            if _is_state_col(norm):
                add(Finding("B", col, "OK",
                            "state-level geography is outside the classes "
                            "that must be removed"))
            else:
                add(Finding("B", col, "VIOLATION",
                            "column appears to hold a geographic subdivision "
                            "smaller than a state (street/city/county/"
                            "geocode), which must be removed"))
            continue

        # --- class C: dates ------------------------------------------------
        if letter == "C":
            precise, _n = _first_hits(nonempty, RE_DATE_PRECISE)
            nonyear = [v for v in nonempty if not RE_YEAR.match(v)]
            if precise or (nonyear and len(nonyear) == len(nonempty)):
                add(Finding("C", col, "VIOLATION",
                            f"date values more precise than year: "
                            f"{(precise or nonyear)[:3]}; only the year "
                            f"may be kept"))
            elif nonyear:
                add(Finding("C", col, "VIOLATION",
                            f"some values are not a bare year: "
                            f"{nonyear[:3]}"))
            elif not nonempty:
                add(Finding("C", col, "OK",
                            "column contains no values -- nothing to "
                            "check"))
            elif _is_birth_col(norm):
                # Class (C) also covers "all elements of dates
                # (including year) indicative of an age over 89": a
                # birth year far enough in the past shows that age by
                # itself, so the year may not stay either.
                from datetime import date as _date
                this_year = _date.today().year
                old = [v for v in nonempty
                       if this_year - int(v) > 90]
                if old:
                    add(Finding("C", col, "VIOLATION",
                                f"birth year(s) {old[:3]} show an age "
                                f"over 89 by themselves (more than 90 "
                                f"years before {this_year}); class (C) "
                                f"requires elements of dates, including "
                                f"the year, that indicate an age over 89 "
                                f"to be removed or aggregated with the "
                                f"age as '90+'"))
                else:
                    add(Finding("C", col, "OK",
                                "all values are a bare year"))
            else:
                add(Finding("C", col, "OK", "all values are a bare year"))
            continue

        # --- value-pattern classes ----------------------------------------
        pattern_for = {"D": RE_PHONE, "F": RE_EMAIL, "G": RE_SSN,
                       "N": RE_URL, "O": RE_IPV4}
        if letter in pattern_for:
            hits, n = _first_hits(nonempty, pattern_for[letter])
            if letter == "O" and not hits:
                v6 = [v for v in nonempty if _has_ipv6(v)]
                if v6:
                    hits, n = v6[:3], len(v6)
            if hits:
                add(Finding(letter, col, "VIOLATION",
                            f"values matching this identifier class: "
                            f"{hits} ({n} row(s))"))
            else:
                add(Finding(letter, col, "VIOLATION",
                            "column name indicates this identifier class; "
                            "its presence in the file is itself the "
                            "problem, whatever the values look like"))
            continue

        # --- name-only classes (A, E, H-M, P, Q) ---------------------------
        if letter is not None:
            add(Finding(letter, col, "VIOLATION",
                        "column name indicates this identifier class; "
                        "presence of the column is flagged because the "
                        "values cannot be told apart mechanically"))
            continue

        # --- unclassified column: scan the values for anything hiding -----
        found_any = False
        for lab, rx, let in (("SSN", RE_SSN, "G"), ("email", RE_EMAIL, "F"),
                             ("phone number", RE_PHONE, "D"),
                             ("URL", RE_URL, "N"), ("IP address", RE_IPV4, "O"),
                             ("precise date", RE_DATE_PRECISE, "C")):
            hits, n = _first_hits(nonempty, rx)
            if hits:
                add(Finding(let, col, "VIOLATION",
                            f"unlabelled column contains {lab}-like "
                            f"value(s): {hits} ({n} row(s))"))
                found_any = True
        v6 = [v for v in nonempty if _has_ipv6(v)]
        if v6:
            add(Finding("O", col, "VIOLATION",
                        f"unlabelled column contains IP address-like "
                        f"value(s): {v6[:3]} ({len(v6)} row(s))"))
            found_any = True
        # Long, sentence-like values in an unlabelled column behave like
        # free text even if the column name does not say so.
        if nonempty and sum(len(v) for v in nonempty) / len(nonempty) > 60:
            add(Finding("R", col, "CANNOT_VERIFY",
                        "values are long and sentence-like (average over "
                        "60 characters): treated as free text -- cannot "
                        "verify, manual review required"))
            found_any = True
        if not found_any:
            add(Finding("-", col, "OK",
                        "no identifier pattern or class-name match found "
                        "by the mechanical checks"))

    # Class (R) and the actual-knowledge condition can never be checked.
    add(Finding("R", "(whole file)", "CANNOT_VERIFY",
                "class (R) -- any other unique identifying number, "
                "characteristic, or code -- cannot be verified "
                "mechanically; nor can the rule's 'no actual knowledge' "
                "condition"))
    return result


def format_report(result, source_name):
    restricted, src = load_restricted_zip3()
    lines = []
    lines.append("safeharbor-check -- Safe Harbor checker report")
    lines.append(f"file checked : {source_name}")
    lines.append(f"rows         : {result.rows}")
    lines.append(f"columns      : {len(result.columns)}")
    lines.append("")
    lines.append("WHAT THIS IS: a mechanical checker for structured CSVs "
                 "against the")
    lines.append("identifier classes in 45 CFR 164.514(b)(2). It is a "
                 "checker only.")
    lines.append("A clean result here does not certify that a file meets "
                 "HIPAA")
    lines.append("requirements. Research/educational tool -- not a medical "
                 "device,")
    lines.append("not legal advice.")
    lines.append("")
    lines.append(RESIDUAL_RISK_NOTE)
    lines.append("")
    lines.append(ZIP_LIST_WARNING)
    lines.append(f"Bundled restricted ZIP prefixes: {len(restricted)} "
                 f"({src}).")
    lines.append("")
    lines.append("PER-CLASS RESULTS (A)-(R)")
    by_letter = {}
    for f in result.findings:
        by_letter.setdefault(f.letter, []).append(f)
    for letter, title in CLASSES:
        checkability = CHECKABILITY_TEXT[CHECKABILITY[letter]]
        fs = by_letter.get(letter, [])
        if not fs:
            status = ("no column detected for this class (detection is "
                      "by column name and value patterns, so this is "
                      "'not detected', not 'proven absent')")
            lines.append(f"  ({letter}) {title}")
            lines.append(f"       checkable: {checkability}")
            lines.append(f"       result   : {status}")
            continue
        lines.append(f"  ({letter}) {title}")
        lines.append(f"       checkable: {checkability}")
        for f in fs:
            lines.append(f"       [{f.status}] column {f.column!r}: "
                         f"{f.detail}")
    extra = by_letter.get("-", [])
    if extra:
        lines.append("  Columns with no class match:")
        for f in extra:
            lines.append(f"       [{f.status}] column {f.column!r}: "
                         f"{f.detail}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  violations found        : {len(result.violations)}")
    lines.append(f"  columns that cannot be  : {len(result.unverified)}")
    lines.append("    verified mechanically")
    lines.append("  always unverifiable     : class (R) and the 'no actual "
                 "knowledge'")
    lines.append("    (standing items)          condition -- see RESIDUAL "
                 "RISK above")
    if result.violations:
        verdict = ("VIOLATIONS FOUND -- the file fails mechanical checks "
                   "listed above.")
    elif result.unverified:
        verdict = ("NO MECHANICAL VIOLATIONS FOUND, but some items "
                   "CANNOT BE VERIFIED (see above) -- this file has not "
                   "passed; it has only not failed the checks that can "
                   "be run.")
    else:
        verdict = ("NO MECHANICAL VIOLATIONS FOUND in the checks this "
                   "tool can perform. This is not a certification of "
                   "any kind -- see RESIDUAL RISK above.")
    lines.append(f"  verdict                 : {verdict}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------

DATE_FORMATS = (
    "%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%m-%d-%Y", "%d %b %Y",
    "%B %d, %Y", "%b %d, %Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
    "%B %Y", "%b %Y", "%Y-%m", "%m.%d.%Y", "%d.%m.%Y",
)


def date_to_year(value, column):
    v = value.strip()
    if not v:
        return ""
    if RE_YEAR.match(v):
        return v
    from datetime import datetime
    for fmt in DATE_FORMATS:
        try:
            return str(datetime.strptime(v, fmt).year)
        except ValueError:
            continue
    raise SafeHarborError(
        f"column {column!r}: cannot read date value {value!r} in any "
        f"supported format, and this tool will not guess. Supported: "
        f"YYYY-MM-DD, YYYY/MM/DD, MM/DD/YYYY, MM-DD-YYYY, '4 Mar 2021', "
        f"'March 4, 2021', 'March 2021', YYYY-MM, DD.MM.YYYY / "
        f"MM.DD.YYYY, ISO date-times, or a bare year.")


def zip_transform(value, restricted):
    v = value.strip()
    if not v:
        return "", "empty, left empty"
    if v == "000":
        return "000", "already 000"
    if RE_ZIP5.match(v):
        prefix = v[:3]
        if prefix in restricted:
            return "000", (f"{v} -> 000 (prefix {prefix} is in the "
                           f"bundled restricted list)")
        return prefix, f"{v} -> {prefix} (first three digits kept)"
    if RE_ZIP3.match(v):
        if v in restricted:
            return "000", (f"{v} -> 000 (prefix is in the bundled "
                           f"restricted list)")
        return v, f"{v} kept as a 3-digit prefix"
    raise SafeHarborError(
        f"cannot read ZIP value {value!r}: expected 5 digits, "
        f"ZIP+4 (12345-6789), 3 digits, or 000 -- refusing to guess")


def age_transform(value, column):
    v = value.strip()
    if not v:
        return ""
    if _is_age_aggregate(v):
        return "90+"
    try:
        age = float(v)
    except ValueError:
        raise SafeHarborError(
            f"column {column!r}: age value {value!r} is not a number "
            f"and not the '90+' aggregate -- refusing to guess")
    if age > 89:
        return "90+"
    if age < 0:
        raise SafeHarborError(
            f"column {column!r}: negative age {value!r} -- refusing")
    return str(int(age)) if age == int(age) else v


@dataclass
class ApplyResult:
    fieldnames: list
    rows: list
    log_lines: list


def apply_data(fieldnames, rows, *, date_cols=(), zip_cols=(), age_cols=(),
               drop_cols=()):
    restricted, src = load_restricted_zip3()
    declared = {}
    for c in date_cols:
        declared[c] = "date"
    for c in zip_cols:
        declared[c] = "zip"
    for c in age_cols:
        declared[c] = "age"
    for c in drop_cols:
        declared[c] = "drop"
    missing = [c for c in declared if c not in fieldnames]
    if missing:
        raise SafeHarborError(
            f"declared column(s) not in the file: {', '.join(missing)}. "
            f"Columns present: {', '.join(fieldnames)}")
    if not declared:
        raise SafeHarborError(
            "apply mode changes nothing unless you declare columns: use "
            "--dates, --zips, --ages and/or --drop. Undeclared columns "
            "are never touched, by design.")

    counts = {"date": 0, "zip": 0, "zip_to_000": 0, "age": 0, "drop": 0}
    zip_examples = []
    out_fields = [c for c in fieldnames if declared.get(c) != "drop"]
    out_rows = []
    for row in rows:
        new = {}
        for col in out_fields:
            v = str(row.get(col) or "")
            role = declared.get(col)
            if role == "date":
                new_v = date_to_year(v, col)
                if new_v != v:
                    counts["date"] += 1
                new[col] = new_v
            elif role == "zip":
                new_v, why = zip_transform(v, restricted)
                if new_v != v:
                    counts["zip"] += 1
                    if new_v == "000":
                        counts["zip_to_000"] += 1
                    if len(zip_examples) < 5:
                        zip_examples.append(why)
                new[col] = new_v
            elif role == "age":
                new_v = age_transform(v, col)
                if new_v != v:
                    counts["age"] += 1
                new[col] = new_v
            else:
                new[col] = v  # undeclared: copied through unchanged
        out_rows.append(new)
    counts["drop"] = len(drop_cols)

    log = []
    log.append("safeharbor-check -- transform log")
    log.append("Only the columns declared on the command line were "
               "changed.")
    log.append("Every other column was copied through unchanged.")
    log.append("")
    for c in drop_cols:
        log.append(f"  dropped column          : {c}")
    for c in date_cols:
        log.append(f"  date column -> year only: {c}")
    for c in zip_cols:
        log.append(f"  ZIP column -> 3 digits / 000: {c}")
    for c in age_cols:
        log.append(f"  age column -> '90+' above 89: {c}")
    log.append("")
    log.append(f"  date values changed     : {counts['date']}")
    log.append(f"  ZIP values changed      : {counts['zip']} "
               f"(of those, set to 000: {counts['zip_to_000']})")
    for ex in zip_examples:
        log.append(f"    e.g. {ex}")
    log.append(f"  age values changed      : {counts['age']}")
    log.append(f"  rows in / out           : {len(rows)} / {len(out_rows)}")
    log.append("")
    log.append(ZIP_LIST_WARNING)
    log.append(f"Bundled restricted ZIP prefixes: {len(restricted)} ({src}).")
    log.append("")
    log.append(RESIDUAL_RISK_NOTE)
    log.append("")
    log.append("This log records mechanical changes only. Running apply "
               "does not certify")
    log.append("that the output meets HIPAA requirements; columns you did "
               "not declare")
    log.append("were not examined or changed, and free-text content was "
               "not reviewed.")
    return ApplyResult(out_fields, out_rows, log)


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
