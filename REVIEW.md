# REVIEW.md — independent adversarial review of safeharbor-check

Reviewer: independent subagent (did not build this tool). Date: 2026-11-17.
Scope: the gauntlet was run locally; at review time nothing had been published, pushed, or posted. Documented
design decisions were NOT changed: unlisted ZIP prefixes → CANNOT_VERIFY
(never safe); free-text columns → CANNOT_VERIFY (never passed); `apply`
touches only user-declared columns.

## Test battery

- Before fixes: `python3 run_tests.py` → **37 tests, all OK**.
- After fixes: **48 tests, all OK** (11 regression tests added).

## (a) Adversarial review — attempts and outcomes

Held correctly (no change): renamed headers backstopped by value scans
(`patient_contact` with a phone/email value → VIOLATION; `dob2` with a
precise date → VIOLATION); `zip_code_ext` with ZIP+4/ZIP-5 → VIOLATION;
header/value casing and whitespace tricks (`Patient_Name`, `ZIP CODE`,
` zip_code `, padded values) all caught; ZIP rules exact (036xx and
3-digit `036` → VIOLATION, 3-digit `941` → CANNOT_VERIFY exit 3, `000`
→ OK, ZIP+4 → VIOLATION); ages exact (89 OK; 89.5/90/95 → VIOLATION;
`90+` / `90 or older` / `>=90` OK); dashed SSN, phone in `(555)`,
dot and `+1` forms, email, IPv4, URL caught in unlabelled columns;
established free-text headers (`notes`, `comment`, `remarks`,
`description`, `narrative`, `clinician_notes`…) → CANNOT_VERIFY, and
long sentence-like values in unlabelled columns → CANNOT_VERIFY;
empty file and header-only file → clean error, exit 2, no traceback.

Found and fixed:

1. **MEDIUM — precise dates evaded the unlabelled-column scan in
   several formats.** In a labelled date column they were flagged (any
   non-year value is flagged there), but in a renamed/unlabelled
   column `2021/03/04`, `2021-03-04T10:00:00`, `4 Mar 2021`,
   `March 2021`, `2021-03`, `20210304`, and `03.04.2021` all passed
   with exit 0. Fixed: `RE_DATE_PRECISE` extended to those forms;
   regression tests added; no false positives on control values
   (`S-001`, bare years, `version 1.2.3`, site labels).
2. **MEDIUM — IPv6 addresses were never detected in values.**
   `RE_IPV6` was defined but used nowhere: `2001:db8::1` in an
   unlabelled column passed, and free-text evidence missed it.
   Fixed: validated with the stdlib `ipaddress` module (`_has_ipv6`)
   in the class-(O), unlabelled, and free-text scans — deliberately
   not a looser regex, so times (`10:20:30`) and MAC-like strings do
   not false-positive (guard test included). Dead `RE_IPV6` removed.
3. **MEDIUM — free-text headers `summary`, `observations`, `details`,
   `history`, `visit_reason` passed** (short free-text values, exit
   0), against the rule that free text never passes. Fixed: hints
   extended (`summary`, `observation`, `detail`, `history`, `memo`,
   `annotation`, `reason`) → all now CANNOT_VERIFY.
4. **MEDIUM — birth years indicating an age over 89 passed.**
   `birth_year=1900/1930`, `dob=1925` (bare years) reported OK, but
   45 CFR 164.514(b)(2)(i)(C) covers "all elements of dates
   (including year) indicative of such age". Fixed narrowly: for
   birth/DOB columns only, a bare year more than 90 years before the
   current year is a VIOLATION; non-birth date columns keep the plain
   year rule (`admission_date=1900` still OK; test included).
5. **LOW — `years_old` / `yrs_old` were not recognised as age
   columns** (`years_old=95` passed). Fixed in `_is_age_col`.
6. **LOW — duplicate CSV headers silently hid a column** (DictReader
   keeps only one), so its values escaped every check. Fixed:
   `read_csv` now refuses duplicate column names with a clean error.
7. **LOW — misleading OK wording for empty columns** ("all ZIP
   values are '000'" / "all values are a bare year" when a column had
   no values at all). Fixed: reports "column contains no values".
8. **LOW — the `90+` aggregate with a space (`90 +`) was flagged as a
   violation in `check` and hard-refused in `apply`.** Fixed: one
   whitespace/case-tolerant `_is_age_aggregate` used by both.
9. **LOW — `apply` refused month-year dates it could read
   unambiguously** (`March 2021`, `2021-03`, `03.04.2021` — the year
   is the same under either day/month order). Fixed: formats added
   to `DATE_FORMATS` and to the error message's supported list.

Known limits left as-is (documented behaviour, safe to leave):
SSNs without dashes (`123456789`) and fully concatenated phone
numbers (`5551234567`) in unlabelled columns are not pattern-matched
— indistinguishable from ordinary numeric IDs, and the README states
the SSN pattern is `NNN-NN-NNNN`; name/MRN-shaped values in a column
called `field_7` are not detectable (README says exactly this);
a bare `cell` header is not name-flagged (ambiguous with biological
cells; formatted numbers in it are still caught by the value scan).

## (b) Oracle verification vs 45 CFR 164.514(b)(2)

Direct eCFR fetch failed (browser service error), so the regulation
text was verified through the HHS de-identification guidance
(Nov 26, 2012), which quotes §164.514(b)(2)(i) verbatim, plus
corroborating sources quoting the same text. Verified verbatim:
(A) Names; (B) geographic subdivisions smaller than a State incl.
street/city/county/precinct/ZIP/geocodes, with the >20,000-population
first-three-digits exception and the change-to-000 rule; (C) all
elements of dates (except year) for dates directly related to an
individual, and all ages over 89 and all elements of dates
(including year) indicative of such age, aggregable to "age 90 or
older"; and the (b)(2)(ii) no-actual-knowledge condition. The
remaining classes (D) telephone, (E) fax, (F) email, (G) SSN,
(H) medical record, (I) health plan beneficiary, (J) account,
(K) certificate/license, (L) vehicle, (M) device, (N) Web URLs,
(O) IP addresses, (P) biometric, (Q) full-face photographs,
(R) any other unique identifying number/characteristic/code match
the tool's `CLASSES` list in wording and order.

The tool's claimed split is accurate: value-checked (B), (C), (D),
(F), (G), (N), (O); name-only (A), (E), (H)–(M), (P), (Q); never
verifiable (R) plus the actual-knowledge condition, which every
report carries as CANNOT VERIFY. The one inaccuracy found was the
(C) birth-year clause (finding 4 above) — fixed. The ZIP handling
matches the regulation's "current Census data" wording honestly:
the bundled list is the HHS 17 prefixes from the 2000 Census, and
unlisted prefixes are reported CANNOT_VERIFY, never safe.

## (c) Fresh install + README demo

- `python3 -m venv` (system Python 3.12.3) worked — ensurepip is
  slow (~25 s) but no failure; no `pip --target` fallback was
  needed. (An earlier /tmp venv was reaped between steps and was
  recreated; the astro-tools venv python was not needed.)
- `pip install ~/workspace/medicine-tools/safeharbor-check` in the
  fresh venv: success; `safeharbor-check` entry point runs, demo
  check exits 1 as documented, IPv6 probe flagged by the installed
  binary, and the full suite passes under the venv python (48 OK).
- README demo reproduced exactly: `check` report is byte-identical
  to `examples/patients_fake_report.txt` when invoked with the
  README's path, and `apply` output is byte-identical to
  `examples/patients_fake_transformed.csv` (94110→941, 03601→000,
  95→90+) and to the README's CSV block; transform log matches the
  stored example. Re-verified again after all fixes: still exact.

## (e) Forbidden-claims wording check

Grepped the whole tree for `de-identifier`, `de-identified`,
`HIPAA compliant`, `HIPAA compliance`, `compliant`, `certified`,
`guarantee`. **No positive claim exists anywhere.** Every hit is a
negation or a class name: "not a certifying tool", "does not
certify", "A transformed file is not a certified file", "it
certifies nothing", and "(K) Certificate / license numbers" (the
regulation's own class name). README's first screen states it is a
CHECKER, "Research/educational tool. Not a medical device.", and
that a clean report does not mean a file meets HIPAA requirements.
Reports and transform logs carry the residual-risk note, the
ZIP-list limit, and "does not certify" in every output — verified
in the reproduced demo files.

## Files changed

- `safeharbor_check/core.py` — findings 1–9 above.
- `tests/test_safeharbor_check.py` — 11 regression tests added
  (`AdversarialReviewTests`).
- `README.md` — test count 37 → 48; class-(C) table row now
  mentions the birth-year rule.
- `REVIEW.md` — this file.
