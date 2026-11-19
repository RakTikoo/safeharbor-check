# Contributing

Thanks for looking. safeharbor-check is a small, single-purpose tool;
these house rules keep changes easy to review.

> **This tool is a checker. It is not a certifying tool.**
> Research/educational tool. Not a medical device. Not legal advice.

## Run the tests

```console
$ python3 run_tests.py
```

All tests must pass before a change is considered. Add tests in `tests/`
for any new behaviour, using synthetic fixtures only — never real data,
not even "anonymised" real data.

## House rules

- Keep the tool single-purpose and dependency-free (standard library
  only).
- **CANNOT VERIFY is never a pass.** Anything that cannot be checked
  mechanically is reported CANNOT VERIFY, in every report. A change
  that turns an unverifiable item into a pass, or drops it from the
  report, will not be accepted — that rule is the product.
- "Not detected" never becomes "proven absent", in code output or in
  docs.
- The bundled ZIP list's vintage (HHS guidance of November 26, 2012,
  2000 Census) is stated in the data file, every report and every
  transform log; keep it stated everywhere the list is used.
- The README's Honest limits section is a promise. If a change alters
  a documented limit or behaviour, update the README in the same pull
  request — and SKILL.md too if the CLI, its flags or its exit codes
  changed.
- Plain words in docs and messages. No marketing language.

## Claiming an issue

Comment on the issue saying you are taking it, then open a pull request
that mentions the issue number.
