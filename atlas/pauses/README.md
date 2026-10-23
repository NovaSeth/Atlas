# Contract pauses

A pause is a file `$SENTINEL_ATLAS/pauses/<id>` that silences one health contract on purpose.
Silencing an alarm is a deliberate decision, so the file must say why, who decided and when.

Which ids exist is up to your contracts:

- a job contract in `$SENTINEL_ATLAS/jobs.d/*.sh` checks `paused <id>` (see `examples/jobs.d/`);
- `sentinel-stream`: escalation does not alarm about a silent stream daemon (deliberately stopped).

## Pause

Create the file. First line = the reason; then who decided and the date (free text).

    printf 'vendor API down, nothing to publish\nadmin, 2026-01-15\n' > "$SENTINEL_ATLAS/pauses/nightly-backup"

## Resume

Delete the file. The contract is checked again from the next patrol run.

## Warning

A pause silences a contract completely, so it MUST carry a reason and a date. Without them nobody
can tell later whether the silence is still wanted. Other contracts are unaffected. If your state
directory is under version control, commit pauses like any other reviewable decision.

Tests only: `JOBS_PAUSE_DIR` overrides the pause directory and `JOBS_D` the contract directory.
