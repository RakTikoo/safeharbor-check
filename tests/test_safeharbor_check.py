"""Tests for safeharbor-check.

All fixtures are synthetic (fake people, fake numbers) and built in
code. Run from the repo root:  python3 run_tests.py
"""

import csv
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from safeharbor_check import core  # noqa: E402


def check(rows, fieldnames=None):
    fieldnames = fieldnames or list(rows[0].keys())
    return core.check_data(fieldnames, rows)


def statuses(result, letter=None, column=None):
    out = []
    for f in result.findings:
        if letter and f.letter != letter:
            continue
        if column and f.column != column:
            continue
        out.append(f.status)
    return out


def run_cli(*argv):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "safeharbor_check", *argv],
        capture_output=True, text=True, cwd=ROOT, env=env)


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


class DateRuleTests(unittest.TestCase):
    def test_precise_date_is_violation(self):
        r = check([{"admission_date": "2021-03-04"}])
        self.assertIn("VIOLATION", statuses(r, "C", "admission_date"))

    def test_us_date_is_violation(self):
        r = check([{"visit_date": "3/4/2021"}])
        self.assertIn("VIOLATION", statuses(r, "C", "visit_date"))

    def test_year_only_is_ok(self):
        r = check([{"admission_date": "2021"}, {"admission_date": "2019"}])
        self.assertEqual(statuses(r, "C", "admission_date"), ["OK"])


class AgeRuleTests(unittest.TestCase):
    def test_age_over_89_is_violation(self):
        r = check([{"age": "42"}, {"age": "95"}])
        self.assertIn("VIOLATION", statuses(r, "C", "age"))

    def test_age_90_plus_aggregate_is_ok(self):
        r = check([{"age": "42"}, {"age": "90+"}])
        self.assertEqual(statuses(r, "C", "age"), ["OK"])

    def test_age_exactly_89_is_ok_90_is_not(self):
        self.assertEqual(statuses(check([{"age": "89"}]), "C", "age"),
                         ["OK"])
        self.assertIn("VIOLATION",
                      statuses(check([{"age": "90"}]), "C", "age"))


class ZipRuleTests(unittest.TestCase):
    def test_zip5_is_violation(self):
        r = check([{"zip_code": "94110"}])
        self.assertIn("VIOLATION", statuses(r, "B", "zip_code"))

    def test_zip_plus4_is_violation(self):
        r = check([{"zip_code": "94110-1234"}])
        self.assertIn("VIOLATION", statuses(r, "B", "zip_code"))

    def test_restricted_zip3_is_violation(self):
        # 036 is one of the 17 HHS-published restricted prefixes.
        r = check([{"zip_code": "036"}])
        self.assertIn("VIOLATION", statuses(r, "B", "zip_code"))

    def test_unrestricted_zip3_is_not_passed_it_is_unverified(self):
        # 941 is not in the bundled list, but the list is from the
        # 2000 Census: the tool must NOT report this as verified OK.
        r = check([{"zip_code": "941"}])
        self.assertEqual(statuses(r, "B", "zip_code"), ["CANNOT_VERIFY"])
        self.assertEqual(r.exit_code, 3)

    def test_zip_000_is_ok(self):
        r = check([{"zip_code": "000"}])
        self.assertEqual(statuses(r, "B", "zip_code"), ["OK"])

    def test_bundled_zip_list_is_the_hhs_17(self):
        prefixes, src = core.load_restricted_zip3()
        self.assertEqual(len(prefixes), 17)
        for p in ("036", "059", "063", "102", "203", "556", "692", "790",
                  "821", "823", "830", "831", "878", "879", "884", "890",
                  "893"):
            self.assertIn(p, prefixes)
        self.assertIn("2012", src)


class PatternClassTests(unittest.TestCase):
    def test_ssn_pattern_flagged(self):
        r = check([{"study_code": "123-45-6789"}])
        self.assertIn("VIOLATION", statuses(r, "G"))

    def test_ssn_column_flagged(self):
        r = check([{"ssn": "123-45-6789"}])
        self.assertIn("VIOLATION", statuses(r, "G", "ssn"))

    def test_phone_column_and_pattern_flagged(self):
        r = check([{"phone_number": "555-123-4567"}])
        self.assertIn("VIOLATION", statuses(r, "D", "phone_number"))

    def test_phone_pattern_hiding_in_unlabelled_column(self):
        r = check([{"contact": "call 555-123-4567"}])
        self.assertIn("VIOLATION", statuses(r, "D", "contact"))

    def test_email_flagged(self):
        r = check([{"email_address": "fake.person@example.invalid"}])
        self.assertIn("VIOLATION", statuses(r, "F", "email_address"))

    def test_url_and_ip_flagged(self):
        r = check([{"website_url": "https://example.invalid/x"},
                   ])
        self.assertIn("VIOLATION", statuses(r, "N", "website_url"))
        r = check([{"ip_address": "192.0.2.10"}])
        self.assertIn("VIOLATION", statuses(r, "O", "ip_address"))


class NameOnlyClassTests(unittest.TestCase):
    def test_name_column_flagged(self):
        r = check([{"patient_name": "Fake Person"}])
        self.assertIn("VIOLATION", statuses(r, "A", "patient_name"))

    def test_mrn_column_flagged(self):
        r = check([{"mrn": "0001234567"}])
        self.assertIn("VIOLATION", statuses(r, "H", "mrn"))

    def test_address_and_city_flagged(self):
        r = check([{"street_address": "1 Fake Street", "city": "Faketown"}])
        self.assertIn("VIOLATION", statuses(r, "B", "street_address"))
        self.assertIn("VIOLATION", statuses(r, "B", "city"))

    def test_other_name_only_classes_flagged(self):
        cases = [
            ({"fax_number": "555-123-4567"}, "E"),
            ({"health_plan_id": "HP-998877"}, "I"),
            ({"account_number": "AC-112233"}, "J"),
            ({"license_number": "LIC-4455"}, "K"),
            ({"vehicle_vin": "1FAKEVIN00000000"}, "L"),
            ({"device_serial": "SN-778899"}, "M"),
            ({"fingerprint_id": "FP-001"}, "P"),
            ({"photo_file": "face1.jpg"}, "Q"),
        ]
        for row, letter in cases:
            with self.subTest(letter=letter):
                self.assertIn("VIOLATION", statuses(check([row]), letter))

    def test_state_column_is_not_flagged(self):
        r = check([{"state": "CA"}])
        self.assertNotIn("VIOLATION", statuses(r, column="state"))


class FreeTextTests(unittest.TestCase):
    def test_free_text_column_cannot_verify_never_passes(self):
        r = check([{"clinician_notes": "Seen today. Doing well."}])
        col_status = statuses(r, column="clinician_notes")
        self.assertEqual(col_status, ["CANNOT_VERIFY"])
        self.assertNotIn("OK", col_status)
        self.assertEqual(r.exit_code, 3)

    def test_free_text_with_identifier_inside_reports_both(self):
        r = check([{"notes": "Call the patient at 555-123-4567 soon."}])
        f = [x for x in r.findings if x.column == "notes"][0]
        self.assertEqual(f.status, "CANNOT_VERIFY")
        self.assertIn("ALSO FOUND", f.detail)

    def test_report_always_carries_residual_risk_note(self):
        r = check([{"age": "42"}])
        report = core.format_report(r, "x.csv")
        self.assertIn("RESIDUAL RISK", report)
        self.assertIn("cannot be verified", report)
        self.assertIn("CANNOT VERIFY", report)
        self.assertIn("ZIP LIST LIMIT", report)
        # The report must never certify anything.
        self.assertIn("does not certify", report)


class CleanFileTests(unittest.TestCase):
    def test_clean_file_passes_mechanical_checks(self):
        rows = [
            {"study_id": "S-001", "birth_year": "1960", "age": "66",
             "state": "CA", "zip_code": "000", "sex": "F"},
            {"study_id": "S-002", "birth_year": "1985", "age": "41",
             "state": "VT", "zip_code": "000", "sex": "M"},
        ]
        r = check(rows)
        self.assertEqual(r.violations, [])
        self.assertEqual(r.unverified, [])
        self.assertEqual(r.exit_code, 0)
        report = core.format_report(r, "clean.csv")
        self.assertIn("NO MECHANICAL VIOLATIONS FOUND", report)
        # ... and even then the residual-risk note is present.
        self.assertIn("RESIDUAL RISK", report)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"study_id": "S-001", "admission_date": "2021-03-04",
             "zip_code": "94110", "age": "95", "ssn": "123-45-6789",
             "site_label": "alpha, ward 3"},
            {"study_id": "S-002", "admission_date": "March 4, 2020",
             "zip_code": "03601", "age": "42", "ssn": "987-65-4321",
             "site_label": "beta, ward 1"},
        ]
        self.fields = list(self.rows[0].keys())

    def test_apply_transforms_declared_columns(self):
        out = core.apply_data(
            self.fields, self.rows, date_cols=("admission_date",),
            zip_cols=("zip_code",), age_cols=("age",), drop_cols=("ssn",))
        self.assertNotIn("ssn", out.fieldnames)
        self.assertEqual(out.rows[0]["admission_date"], "2021")
        self.assertEqual(out.rows[1]["admission_date"], "2020")
        self.assertEqual(out.rows[0]["zip_code"], "941")
        # 03601 -> prefix 036 is restricted -> 000
        self.assertEqual(out.rows[1]["zip_code"], "000")
        self.assertEqual(out.rows[0]["age"], "90+")
        self.assertEqual(out.rows[1]["age"], "42")

    def test_apply_never_touches_undeclared_columns(self):
        out = core.apply_data(
            self.fields, self.rows, date_cols=("admission_date",))
        for before, after in zip(self.rows, out.rows):
            self.assertEqual(after["zip_code"], before["zip_code"])
            self.assertEqual(after["age"], before["age"])
            self.assertEqual(after["ssn"], before["ssn"])
            self.assertEqual(after["site_label"], before["site_label"])
            self.assertEqual(after["study_id"], before["study_id"])

    def test_apply_with_no_declarations_refuses(self):
        with self.assertRaises(core.SafeHarborError):
            core.apply_data(self.fields, self.rows)

    def test_apply_unknown_declared_column_refuses(self):
        with self.assertRaises(core.SafeHarborError):
            core.apply_data(self.fields, self.rows, date_cols=("nope",))

    def test_apply_unreadable_date_refuses_cleanly(self):
        rows = [{"d": "sometime last spring"}]
        with self.assertRaises(core.SafeHarborError):
            core.apply_data(["d"], rows, date_cols=("d",))

    def test_apply_unreadable_zip_refuses_cleanly(self):
        rows = [{"z": "not-a-zip"}]
        with self.assertRaises(core.SafeHarborError):
            core.apply_data(["z"], rows, zip_cols=("z",))

    def test_apply_log_carries_warnings(self):
        out = core.apply_data(
            self.fields, self.rows, zip_cols=("zip_code",))
        log = "\n".join(out.log_lines)
        self.assertIn("ZIP LIST LIMIT", log)
        self.assertIn("RESIDUAL RISK", log)
        self.assertIn("does not certify", log)


class AdversarialReviewTests(unittest.TestCase):
    """Regression tests added by the independent adversarial review."""

    def test_unlabelled_date_formats_flagged(self):
        for value in ("2021/03/04", "2021-03-04T10:00:00", "4 Mar 2021",
                      "March 2021", "2021-03", "20210304", "03.04.2021"):
            with self.subTest(value=value):
                r = check([{"field_x": value}])
                self.assertIn("VIOLATION", statuses(r, "C", "field_x"))

    def test_ipv6_in_unlabelled_column_flagged(self):
        r = check([{"code": "2001:db8::1"}])
        self.assertIn("VIOLATION", statuses(r, "O", "code"))

    def test_ipv6_in_labelled_ip_column_flagged_by_value(self):
        r = check([{"ip_address": "2001:db8::1"}])
        self.assertIn("VIOLATION", statuses(r, "O", "ip_address"))

    def test_time_value_is_not_an_ip(self):
        r = check([{"code": "10:20:30"}])
        self.assertNotIn("VIOLATION", statuses(r, column="code"))

    def test_more_free_text_headers_cannot_verify(self):
        for col in ("summary", "observations", "details", "history",
                    "visit_reason"):
            with self.subTest(col=col):
                r = check([{col: "Patient doing well, follow up soon."}])
                self.assertEqual(statuses(r, column=col),
                                 ["CANNOT_VERIFY"])

    def test_years_old_is_an_age_column(self):
        r = check([{"years_old": "95"}])
        self.assertIn("VIOLATION", statuses(r, "C", "years_old"))
        r = check([{"years_old": "50"}])
        self.assertEqual(statuses(r, "C", "years_old"), ["OK"])

    def test_birth_year_indicating_age_over_89_is_violation(self):
        r = check([{"birth_year": "1900"}])
        self.assertIn("VIOLATION", statuses(r, "C", "birth_year"))
        r = check([{"birth_year": "1960"}])
        self.assertEqual(statuses(r, "C", "birth_year"), ["OK"])
        # A non-birth date column keeps the plain year rule.
        r = check([{"admission_date": "1900"}])
        self.assertEqual(statuses(r, "C", "admission_date"), ["OK"])

    def test_age_aggregate_with_space_is_ok(self):
        r = check([{"age": "90 +"}])
        self.assertEqual(statuses(r, "C", "age"), ["OK"])

    def test_apply_age_aggregate_with_space(self):
        out = core.apply_data(["a"], [{"a": "90 +"}], age_cols=("a",))
        self.assertEqual(out.rows[0]["a"], "90+")

    def test_apply_month_year_and_year_month_dates(self):
        for value in ("March 2021", "2021-03", "03.04.2021"):
            with self.subTest(value=value):
                out = core.apply_data(["d"], [{"d": value}],
                                      date_cols=("d",))
                self.assertEqual(out.rows[0]["d"], "2021")

    def test_duplicate_headers_are_a_clean_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "dup.csv"
            p.write_text("a,a\n1,2\n", encoding="utf-8")
            with self.assertRaises(core.SafeHarborError):
                core.read_csv(p)


class CliTests(unittest.TestCase):
    def test_cli_check_dirty_and_clean(self):
        with tempfile.TemporaryDirectory() as td:
            dirty = Path(td) / "dirty.csv"
            write_csv(dirty, ["patient_name", "age"],
                      [{"patient_name": "Fake Person", "age": "95"}])
            proc = run_cli("check", str(dirty))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("(A) Names", proc.stdout)
            self.assertIn("(R)", proc.stdout)
            self.assertIn("RESIDUAL RISK", proc.stdout)

            clean = Path(td) / "clean.csv"
            write_csv(clean, ["birth_year", "age", "zip_code"],
                      [{"birth_year": "1960", "age": "66",
                        "zip_code": "000"}])
            proc = run_cli("check", str(clean))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_cli_apply_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.csv"
            write_csv(src, ["admission_date", "zip_code", "age", "keep_me"],
                      [{"admission_date": "2021-03-04", "zip_code": "03601",
                        "age": "95", "keep_me": "2021-03-04"}])
            out = Path(td) / "out.csv"
            proc = run_cli("apply", str(src), "--out", str(out),
                           "--dates", "admission_date", "--zips", "zip_code",
                           "--ages", "age")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            text = out.read_text(encoding="utf-8")
            self.assertIn("2021,000,90+,2021-03-04", text)
            self.assertTrue(Path(str(out) + ".log.txt").is_file())

    def test_cli_missing_file_is_clean_error(self):
        proc = run_cli("check", "/nonexistent/nope.csv")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
