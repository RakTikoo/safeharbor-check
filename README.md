# safeharbor-check

**A checker for structured CSVs against the HIPAA Safe Harbor identifier
classes — nothing more.**

> **This tool is a CHECKER. It is not a certifying tool, and a clean
> report from it does not mean a file meets HIPAA requirements.**
> It runs the mechanical checks that can be run on a structured CSV —
> dates more precise than a year, ZIP codes longer than three digits,
> ages over 89, columns that hold names, phone numbers, Social Security
> numbers, and so on — and it reports, in the same breath, everything
> that **cannot** be checked mechanically: free-text columns, class (R)
> ("any other unique identifying number, characteristic, or code"), and
> the rule's "no actual knowledge" condition. Those items are reported
> as **CANNOT VERIFY** in every report. They are never reported as
> passing.
>
> Research/educational tool. Not a medical device. Not legal advice.
> Verify before any real-world use, with a human who knows the data.

The rule it checks against is the Safe Harbor method in
**45 CFR 164.514(b)(2)**, which lists 18 identifier classes, (A)–(R),
that must be removed, with three mechanical exceptions this tool also
implements in its `apply` mode: dates may keep the **year**, ZIP codes
may keep the **first three digits** if the combined population of that
three-digit area is **more than 20,000** (otherwise the prefix becomes
**000**), and ages over 89 are aggregated as **90 or older**.

## Demo

A small file of entirely fake patients
([`examples/patients_fake.csv`](examples/patients_fake.csv)):

```console
$ safeharbor-check check examples/patients_fake.csv
safeharbor-check -- Safe Harbor checker report
file checked : examples/patients_fake.csv
rows         : 3
columns      : 9
...
PER-CLASS RESULTS (A)-(R)
  (A) Names
       checkable: checked by column name only -- values cannot be told apart mechanically
       [VIOLATION] column 'patient_name': column name indicates this identifier class; ...
  (B) Geographic subdivisions smaller than a state (address, city, county, ZIP, geocodes)
       checkable: checked by column name and by value patterns/rules
       [VIOLATION] column 'zip_code': ZIP values longer than 3 digits: ['94110', '03601', '05401'] (3 row(s)); ...
  (C) Dates (all elements except year) and ages over 89
       [VIOLATION] column 'admission_date': date values more precise than year: ['2021-03-04', 'March 4, 2020', '2019-11-20']; ...
       [VIOLATION] column 'age': age value(s) over 89 not aggregated to '90+': ['95'] (1 row(s))
  (D) Telephone numbers
       [VIOLATION] column 'phone_number': values matching this identifier class: ['555-123-4567', ...] (3 row(s))
  ...
  (R) Any other unique identifying number, characteristic, or code
       checkable: cannot be verified mechanically
       [CANNOT_VERIFY] column 'clinician_notes': free-text column: cannot verify -- manual review required
       [CANNOT_VERIFY] column '(whole file)': class (R) ... cannot be verified mechanically; ...

SUMMARY
  violations found        : 5
  verdict                 : VIOLATIONS FOUND -- the file fails mechanical checks listed above.
```

(exit code 1; the full report is in
[`examples/patients_fake_report.txt`](examples/patients_fake_report.txt),
including the residual-risk note and the ZIP-list limit, which appear
in **every** report.)

`apply` fixes only the columns you declare — here it also drops the
three declared identifier columns:

```console
$ safeharbor-check apply examples/patients_fake.csv \
      --out examples/patients_fake_transformed.csv \
      --dates admission_date --zips zip_code --ages age \
      --drop patient_name,phone_number,clinician_notes
wrote examples/patients_fake_transformed.csv (3 rows, 6 columns)
transform log: examples/patients_fake_transformed.csv.log.txt
```

```csv
study_id,admission_date,zip_code,age,state,site_label
S-001,2021,941,90+,CA,"alpha, ward 3"
S-002,2020,000,42,VT,"beta, ward 1"
S-003,2019,054,67,VT,"beta, ward 2"
```

Note `03601 → 000`: prefix 036 is one of the restricted prefixes whose
combined population is 20,000 or fewer. Columns that were not declared
(`study_id`, `state`, `site_label`) are copied through byte-for-value
unchanged — and the transform log says, again, that running `apply`
certifies nothing and that undeclared columns were not examined.

## Install

```console
$ pip install git+https://github.com/RakTikoo/safeharbor-check
```

Python ≥ 3.10, standard library only, fully offline.

## Usage

```
safeharbor-check check FILE [--report FILE]
safeharbor-check apply FILE --out FILE [--log FILE]
                       [--dates COL,...] [--zips COL,...]
                       [--ages COL,...] [--drop COL,...]
```

- `check` exit codes: **0** = no mechanical violations found and no
  column left unverified (the standing class-(R) / actual-knowledge
  note still applies — read it); **1** = violations found; **3** = no
  violations, but at least one column cannot be verified mechanically
  (free text, or a ZIP prefix the bundled list cannot settle).
- `apply` refuses to run with no declared columns, refuses columns
  that are not in the file, and refuses values it cannot read (an
  unparseable date or ZIP in a declared column is a clean error,
  never a guess).

### Which of the 18 classes can actually be checked?

| Class | How it is checked here |
|---|---|
| (A) Names | Column name only — a name is not a pattern |
| (B) Geography below state | Column name **and** value rules (ZIP length, restricted prefixes, `000`) |
| (C) Dates & ages over 89 | Column name **and** value rules (more precise than year; numeric age > 89 not shown as `90+`; a birth year that by itself shows an age over 89) |
| (D) Telephone numbers | Column name **and** value pattern; patterns are also scanned for inside unlabelled and free-text columns |
| (E) Fax numbers | Column name only |
| (F) Email addresses | Column name **and** value pattern |
| (G) Social Security numbers | Column name **and** value pattern (`NNN-NN-NNNN`) |
| (H) Medical record numbers | Column name only — an MRN looks like any other number |
| (I) Health plan beneficiary numbers | Column name only |
| (J) Account numbers | Column name only |
| (K) Certificate / license numbers | Column name only |
| (L) Vehicle identifiers / plates | Column name only |
| (M) Device identifiers / serial numbers | Column name only |
| (N) Web URLs | Column name **and** value pattern |
| (O) IP addresses | Column name **and** value pattern |
| (P) Biometric identifiers | Column name only |
| (Q) Full-face photographs | Column name only — a CSV holds file references at most, never the image itself |
| (R) Any other unique identifying number/characteristic/code | **Cannot be verified mechanically — always reported CANNOT VERIFY** |

"Checked by column name only" means exactly that: if a medical record
number is sitting in a column called `field_7`, this tool will not
find it, and the report's "no column detected" line says *not
detected*, never *proven absent*.

## Honest limits

- **The bundled ZIP list is dated, and the tool says so everywhere.**
  The restricted-prefix list
  ([`safeharbor_check/data/zip3_restricted_hhs.csv`](safeharbor_check/data/zip3_restricted_hhs.csv))
  is the 17 prefixes published by the U.S. Department of Health and
  Human Services in its guidance of **November 26, 2012**, derived
  from the Bureau of the Census **2000 Census** ZIP Code Tabulation
  Areas (first published at 67 FR 53182, 53233–53234, August 14,
  2002). HHS warns in that same guidance not to rely on the list if
  more current Census data is available. **No complete, updated
  restricted list based on a later census was found published by HHS
  or the Census Bureau as of 2026-11-17**, so the list is bundled as
  the best published source — with its vintage stated in the data
  file, in every report, and in every transform log. A prefix that is
  not in the list is reported as *"not flagged by the bundled
  2000-Census list — not verified against current Census data"*,
  never as verified safe. If a current list matters to you, check the
  prefixes in your data against current Census data yourself.
- **Free text is out of scope for verification.** Notes, comments and
  other free-text columns are flagged CANNOT VERIFY (with any concrete
  pattern hits inside them listed as extra evidence), and long,
  sentence-like values in unlabelled columns are treated the same way.
  A person must read them.
- **Column-name detection is a heuristic.** Renamed, abbreviated or
  non-English column names can evade the name-based classes. The
  value-pattern scans (SSN, email, phone, URL, IP, precise dates) run
  on every unlabelled column as a backstop, but classes (H)–(M), (P)
  and (Q) have no value pattern to scan for.
- **Structured CSVs only.** No spreadsheets, no databases, no images,
  no free-text documents.
- **This tool makes no medical judgements of any kind** — no
  diagnosis, no staging, no treatment or dose output. It looks at
  identifier-shaped columns only.
- **A transformed file is not a certified file.** `apply` performs
  the mechanical fixes on the columns you declared. It does not look
  at undeclared columns, it does not read free text for you, and the
  remaining classes and conditions above still apply to the output.

## Tests

```console
$ python3 run_tests.py
```

48 tests (stdlib `unittest`): one synthetic fixture per mechanically
checkable rule — precise dates vs bare years, ZIP-5 / ZIP+4 /
restricted 3-digit prefixes / `000`, ages 89 vs 90 vs the `90+`
aggregate, SSN / phone / email / URL / IP patterns (including patterns
hiding in unlabelled columns), each name-only class, free text
reported CANNOT VERIFY and never passing, a clean file passing the
mechanical checks while still carrying the residual-risk note — plus
`apply`-mode correctness (dates→year, `94110→941`, `03601→000`,
`95→90+`, declared drops), proof that `apply` never touches undeclared
columns, and its refusal rules.

## Use with an AI agent

This repo ships a [SKILL.md](SKILL.md) written to the Agent Skills open
standard. If your coding agent supports skills, point it at this repo
and it can install safeharbor-check, run it on your CSVs, and read the
results for you. The skill works as documented when the repo is cloned
under its real name (`safeharbor-check`) — the standard matches a skill
to its folder name.

## License

MIT. Free and open source, for science.
