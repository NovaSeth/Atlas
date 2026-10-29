# Compatibility

Atlas depends on formats it does not own: the hook input and transcript files of Claude Code (taint gate in
`agent/claude-code/hooks/`) and the fields journald attaches to entries (`sentinel/stream.py`). A format change
can break detection or trust decisions silently, so this page lists exactly what is read and what happens when it
moves.

## Claude Code versions verified

| Claude Code | Status | What was checked |
|---|---|---|
| `2.1.306` | verified, the only one | hook input fields and transcript records below, against the taint gate tests and a live transcript |

Any other version is unverified. The taint gate does not check the version; it checks the shape of what it reads.

## Hook input fields used

Read by `taint_gate.py` and its `tg_*.py` modules (events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`):

| Field | Used for |
|---|---|
| `hook_event_name` | which event is being handled |
| `session_id` | per-session taint state (names are validated or hashed) |
| `tool_name` | which tool is about to run or has run |
| `tool_input` | the command, path or sub-agent type being judged |
| `tool_use_id` | pairing a tool call with its result |
| `tool_response` | the result of a tool, to decide whether untrusted data was read |
| `agent_id` | present inside a sub-agent: its taint is tracked apart from the parent's |
| `agent_type` | which sub-agent (the quarantined reader is allowed) |
| `prompt` | the text of a submitted prompt, matched against the transcript |
| `prompt_id` | links the prompt to its transcript record |
| `transcript_path` | the session transcript, read to prove a prompt came from a person |
| `cwd` | working directory of the call |

## Transcript records used

To clear taint, the gate needs evidence that a human wrote the prompt. It reads the transcript (a JSON line per
record, newest first, the last 200 lines are probed for shape):

| Record | Fields | Meaning |
|---|---|---|
| `type: user` | `promptId`, `promptSource` (`typed` or `queued`), `origin` (absent, `"human"` or `{"kind": "human"}`), `message.content` (text and image blocks only), `timestamp`, `sessionId` | a prompt typed by a person |
| `attachment` of type `queued_command` | `prompt`, `humanTurn` (must be true), `origin` (`"human"` or `{"kind": "human"}`), `delivery_id`, `commandMode` (`prompt`), `timestamp` | a message typed while the agent was busy |
| `queue-operation` with `operation: remove` | `deliveryId`, `timestamp` | the moment a queued message was handed to the model (must be within 10 s) |
| `<task-notification>` envelope in the prompt text | `<task-id>` | a background-task notice: never counts as human, even when it looks like one |

## What happens when a field changes

- **Missing or unrecognised transcript shape.** If none of the last 200 records looks like a transcript record, the
  gate logs `transcript-format-unknown` and keeps the taint: it fails closed. A human then has to be recognised
  another way or the session stays restricted. It never clears taint on a guess.
- **A field renamed or retyped** (`promptSource`, `delivery_id`, `humanTurn`, `promptId`): the record no longer
  proves a human origin, the prompt is treated as unverified and the taint stays.
  **Fail closed:** a `type: user` record is human only with no `origin` key, `"origin": "human"`, or `{"kind": "human"}`;
  anything else (other strings, other objects, an explicit null, numbers, lists) is not human and the taint stays. A queued
  message (`queued_command`) is stricter: it needs `"origin": "human"` or `{"kind": "human"}` (a missing `origin` is not
  enough) and `humanTurn` true.
- **A hook input field missing.** Without `prompt_id` the prompt is treated as unverified. Without `agent_id` the call
  is treated as the main agent's: the per-subagent taint does not apply to it, so a harness change that drops
  `agent_id` weakens enforcement for subagents: the call is judged by the main session's taint only.
- **Hook not run at all** (timeout, crash): the shipped `hooks.json` blocks every non-read-only tool on failure
  and lets reads continue; see [resident.md](resident.md#7-safety-untrusted-data).

## Reporting a new version

Run the tests in `tests/test_taint_gate*.py` against the new version, then look at a fresh session log
(`gate.log` in the gate state directory, or the file named by `TAINT_LOG`) for `transcript-format-unknown`. If it appears, or a typed
prompt does not clear taint, open an issue with the Claude Code version (`claude --version`), the `hook_event_name`
and the **key names** (not values) of the transcript records that changed. Do not paste transcripts: they contain
your conversation.

## journald fields

`sentinel/stream.py` relies on these fields of each journal entry. They are set by journald from the sending
process, not by the message, so a user cannot forge them.

| Field | Used for | Debian 13 (measured 2026-10-29) |
|---|---|---|
| `_SYSTEMD_UNIT` | selects `ssh.service` | present |
| `_PID` | PID 1 = systemd failures | present |
| `_TRANSPORT` | `kernel` messages | present |
| `_UID` | sudo sender must be the invoking user | present |
| `_EXE` | sudo sender must be a configured sudo path (`SENTINEL_SUDO_EXE`) | present for sudo entries |
| `_COMM` | fallback when `_EXE` is missing: must be `sudo` | present |

Other distributions: not measured. If a distribution does not provide `_EXE` for sudo entries, the stream falls back
to `_COMM`, which is weaker (a process can rename itself); check with
`journalctl -o json -n 1 SYSLOG_IDENTIFIER=sudo` after a `sudo true`, and set `SENTINEL_SUDO_EXE` if sudo lives
elsewhere.
