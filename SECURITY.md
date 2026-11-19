# Security policy

## Reporting a problem

Please do not open a public issue for a security problem.

Report it privately through GitHub: open this repository's **Security**
tab and choose **Report a vulnerability**. If that form is not
available, open a regular issue that says only that you have a security
report and asks for a private contact route — do not include any
details in public.

Never include real health data in a report. A synthetic CSV that
reproduces the problem is enough — the bundled
`examples/patients_fake.csv` shows the expected style.

## Scope

safeharbor-check runs locally on CSV files you give it. The realistic
concerns are crashes or wrong results on crafted input files, and
those reports are welcome through the same route.
