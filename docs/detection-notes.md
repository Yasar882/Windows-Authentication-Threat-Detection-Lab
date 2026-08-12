# Detection Notes

## Logic

Three or more Event ID 4625 failures from the same source within a five-minute bucket are treated as suspicious.

## Possible false positives

- Stale credentials
- Expired service-account passwords
- Misconfigured applications
- Administrative activity
- User typing the wrong password repeatedly

## Tuning

- Allowlist known administrative systems.
- Tune service-account exclusions.
- Correlate with Event ID 4624.
- Detect multiple targeted accounts.
- Add risk scoring.
