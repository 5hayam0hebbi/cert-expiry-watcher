# cert-expiry-watcher

Expired and misconfigured TLS certificates still cause outages. This tool checks a list of endpoints every morning in GitHub Actions and opens one GitHub Issue before a certificate becomes an incident.

## What it checks

- Days until expiry: WARN at 21 days or fewer, CRIT at 7 (`--warn`, `--crit` to change)
- Full verification, like a browser: trusted chain, matching host name, not expired, not self-signed
- Connection problems: DNS, refused, timeouts

## Run it

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements-dev.txt
    python certwatch.py endpoints.txt
    python certwatch.py demo-broken.txt   # see every kind of failure

Exit code 1 means something needs attention, so it drops into any CI or cron job.

## How the alerting works

`.github/workflows/check.yml` runs the tests on every push and the certificate check every day at 11:17 UTC. If anything fails it opens an issue labelled `cert-alert`, or comments on the one already open, with a table of the problems.

## Tests

`pytest -v` covers parsing, thresholds and the report, with no network needed.
