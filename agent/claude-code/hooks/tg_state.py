"""Locked session state, persistent registries, optional configuration, logging and the switch."""

import hashlib
import json
import os
import re
import tg_core


_CONFIG = None


CONFIG_KEYS = ("extra_untrusted_tools", "extra_monitor_commands", "extra_untrusted_paths", "subagent_allowlist")


DEFAULT_SUBAGENT_ALLOWLIST = ()  # flip to ("log-reader",) here to restrict launches by default (plan P12)


FAIL_CLOSED_ALLOWLIST = ("log-reader",)  # an invalid config that names the key: the one tightening key fails closed


def _config_problem(path, why):
    """Log an invalid config once per file version (marker in the state dir), best effort."""
    try:
        st = os.stat(path)
        stamp = "%d:%d:%s" % (st.st_mtime_ns, st.st_size, why)
    except OSError:
        stamp = "?:%s" % why
    marker = os.path.join(os.environ.get("TAINT_STATE_DIR") or tg_core.STATE_DIR, "config-invalid")
    try:
        with open(marker, "r", encoding="utf-8") as f:
            if f.read(200) == stamp:
                return
    except OSError:
        pass
    log("-", "config", "-", "ignored", why)
    try:
        d = os.path.dirname(marker)
        os.makedirs(d, mode=0o700, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as f:
            f.write(stamp)
    except OSError:
        pass


def config():
    """The parsed optional config: {key: tuple of strings}; empty values when missing or invalid."""
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG
    empty = {k: () for k in CONFIG_KEYS}
    empty["subagent_allowlist"] = DEFAULT_SUBAGENT_ALLOWLIST
    _CONFIG = empty
    path = os.environ.get("TAINT_CONFIG") or tg_core.CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read(1 << 20)
    except OSError:
        return empty  # no config is the normal case
    try:
        d = json.loads(raw)
        if not isinstance(d, dict):
            raise ValueError("not-an-object")
        out = {}
        for k in CONFIG_KEYS:
            v = d.get(k, [])
            if not isinstance(v, list) or not all(isinstance(x, str) and x and "\x00" not in x for x in v):
                raise ValueError("bad-" + k)
            out[k] = tuple(v)
        if any(not x.startswith("/") for x in out["extra_untrusted_paths"]):
            raise ValueError("bad-extra_untrusted_paths")
        out["extra_untrusted_paths"] = tuple(os.path.normpath(x) for x in out["extra_untrusted_paths"])
        if "subagent_allowlist" not in d:
            out["subagent_allowlist"] = DEFAULT_SUBAGENT_ALLOWLIST
    except ValueError as e:
        _config_problem(path, str(e)[:40] or "invalid")
        if "subagent_allowlist" in raw:
            empty["subagent_allowlist"] = FAIL_CLOSED_ALLOWLIST
        return empty
    _CONFIG = out
    return out


def extra_tool_source(tool):
    for name in config()["extra_untrusted_tools"]:
        if name.endswith("*"):
            if tool.startswith(name[:-1]):
                return "extra-tool"
        elif tool == name:
            return "extra-tool"
    return None


def extra_path_source(path):
    for root in config()["extra_untrusted_paths"]:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return "extra-path"
    return None


def monitor_commands():
    return tg_core.MONITOR_COMMANDS | frozenset(x.strip() for x in config()["extra_monitor_commands"])


ARTIFACTS_FILE = "artifacts.json"


ARTIFACTS_MAX = 5000


FULL_REGISTRY_ROOTS = ("/tmp", "/var/tmp")  # the scratchpad roots live under /tmp


_ARTIFACTS = None


_ARTIFACTS_FULL = False


def artifact_paths():
    """Destinations that received copies of untrusted content; global, all sessions,
    never evicted. Sets _ARTIFACTS_FULL when recording has stopped."""
    global _ARTIFACTS, _ARTIFACTS_FULL
    if _ARTIFACTS is None:
        _ARTIFACTS = ()
        path = os.path.join(os.environ.get("TAINT_STATE_DIR") or tg_core.STATE_DIR, ARTIFACTS_FILE)
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.loads(f.read(4 << 20))
            if isinstance(d, dict) and isinstance(d.get("paths"), list):
                _ARTIFACTS = tuple(x for x in d["paths"] if isinstance(x, str) and x.startswith("/"))
                _ARTIFACTS_FULL = d.get("full") is True
        except (OSError, ValueError):
            pass
    return _ARTIFACTS


LATENT_FILE = "latent.json"


LATENT_MAX = 5000


_LATENT = None


_LATENT_FULL = False


def latent_paths():
    """Scripts written from data text that contains a source marker (write now, execute later)."""
    global _LATENT, _LATENT_FULL
    if _LATENT is None:
        _LATENT = ()
        path = os.path.join(os.environ.get("TAINT_STATE_DIR") or tg_core.STATE_DIR, LATENT_FILE)
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.loads(f.read(4 << 20))
            if isinstance(d, dict) and isinstance(d.get("paths"), list):
                _LATENT = tuple(x for x in d["paths"] if isinstance(x, str) and x.startswith("/"))
                _LATENT_FULL = d.get("full") is True or len(_LATENT) >= LATENT_MAX
        except (OSError, ValueError):
            pass
    return _LATENT


def latent_full():
    latent_paths()
    return _LATENT_FULL


ISO_TIME = tg_core.Lazy(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


PENDING_MAX = 200


def safe_token(s, limit):
    s = s if isinstance(s, str) else ""
    s = re.sub(r"[^A-Za-z0-9_.-]", "", s)[:limit]
    return s or "-"


def state_name(session_id):
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
        return session_id
    return "h-" + hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:32]


class State:
    """Taint state of one session.

    Files in the state dir (700):
      <sid>.json     record: tainted, source, since, count, pending {tool_use_id: source}, ...
      <sid>.tainted  flag: its mere existence means tainted. Creating an empty file needs no data
                     blocks, so the taint survives even when the record cannot be written.
      .lock          fcntl lock serializing every read-modify-write.
    A session with neither file is clean, but only if the state dir is usable; otherwise its state
    is unknown and the tainted policy applies. `unknown` holds a reason code.
    """

    def __init__(self, session_id):
        self.dir = os.environ.get("TAINT_STATE_DIR") or tg_core.STATE_DIR
        self.unknown = None
        self.data = {}
        self.flag = False
        self.path = self.flag_path = None
        self._lock_fd = None
        if not isinstance(session_id, str) or not session_id:
            self.unknown = "no-session"
            return
        name = state_name(session_id)
        self.path = os.path.join(self.dir, name + ".json")
        self.flag_path = os.path.join(self.dir, name + ".tainted")
        try:
            if not os.path.isdir(self.dir):
                if os.path.lexists(self.dir):
                    raise tg_core.GateError("state-dir")
                os.makedirs(self.dir, mode=0o700, exist_ok=True)
            if not os.access(self.dir, os.R_OK | os.W_OK | os.X_OK):
                raise tg_core.GateError("state-dir")
            self.load()
        except tg_core.GateError as e:
            self.unknown = str(e)
        except OSError:
            self.unknown = "state-dir"

    def load(self):
        self.flag = os.path.lexists(self.flag_path)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = f.read(65536)
        except FileNotFoundError:
            self.data = {}
            return
        except OSError:
            raise tg_core.GateError("state-corrupt")
        try:
            d = json.loads(raw)
        except ValueError:
            raise tg_core.GateError("state-corrupt")
        if not isinstance(d, dict) or not isinstance(d.get("tainted"), bool):
            raise tg_core.GateError("state-corrupt")
        self.data = d

    # -- locking
    def __enter__(self):
        if self.path is None or self.unknown == "state-dir":
            return self
        import fcntl

        fd = os.open(os.path.join(self.dir, ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)  # bounded by the internal deadline
        self._lock_fd = fd
        try:
            self.load()  # re-read under the lock: another hook may have changed it
            if self.unknown == "state-corrupt":
                self.unknown = None
        except tg_core.GateError as e:
            self.unknown = str(e)
        return self

    def __exit__(self, *exc):
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # closing releases the flock
            self._lock_fd = None
        return False

    # -- queries
    @property
    def tainted(self):
        return self.flag or self.data.get("tainted") is True

    @property
    def gated(self):
        return self.tainted or self.unknown is not None

    def source_and_since(self):
        if self.unknown:
            return "state unknown: " + self.unknown, tg_core.now_iso()
        src = self.data.get("source") if self.data.get("tainted") is True else None
        since = self.data.get("since")
        if not (isinstance(since, str) and ISO_TIME.fullmatch(since)):
            since = "unknown time"
        return (safe_token(src, 32) if src else "source unknown"), since

    def pending(self):
        p = self.data.get("pending")
        return p if isinstance(p, dict) else {}

    # -- writes (call inside `with state:`)
    def _write(self, d):
        if os.environ.get("TAINT_FAIL_WRITES") in ("json", "all"):
            return False  # test hook: simulate a full filesystem (only ever makes things stricter)
        tmp = "%s.%d.tmp" % (self.path, os.getpid())
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, self.path)
            self.data = d
            return True
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

    def _touch_flag(self):
        if os.environ.get("TAINT_FAIL_WRITES") == "all":
            return False
        try:
            os.close(os.open(self.flag_path, os.O_WRONLY | os.O_CREAT, 0o600))
            self.flag = True
            return True
        except OSError:
            return False

    def mark(self, source, pending_id=None, settle_id=None):
        """Record taint (and a pending untrusted call, or settle one). False = not persisted."""
        if self.path is None:
            return False
        d = dict(self.data) if self.unknown is None else {}
        if d.get("tainted") is True:
            d["count"] = d["count"] + 1 if isinstance(d.get("count"), int) else 1
        else:
            d.update({"tainted": True, "source": source, "since": tg_core.now_iso(), "count": 1})
        d["marked_at"] = tg_core.now_iso_ms()  # every mark: human evidence must be newer than the latest untrusted read
        pend = dict(self.pending()) if self.unknown is None else {}
        if settle_id is not None:
            pend.pop(settle_id, None)
        if pending_id is not None:
            pend[pending_id] = source
            while len(pend) > PENDING_MAX:
                pend.pop(next(iter(pend)))
        d["pending"] = pend
        if self._write(d):
            self.unknown = None
            return True
        return self._touch_flag()

    def add_artifacts(self, paths):
        """Remember destinations of copied untrusted content (global list, under the lock): the
        literal path and its realpath (a symlink destination writes into its target). Never
        evicts; past ARTIFACTS_MAX recording stops and the registry is marked full (D4)."""
        want = []
        for p in paths:
            if isinstance(p, str) and p.startswith("/") and p != "/":
                want.append(os.path.normpath(p))
                try:
                    want.append(os.path.realpath(p))
                except (OSError, ValueError):
                    pass
        if not want or os.environ.get("TAINT_FAIL_WRITES") in ("json", "all"):
            return bool(not want)
        global _ARTIFACTS, _ARTIFACTS_FULL
        _ARTIFACTS = None
        cur = list(artifact_paths())
        full = _ARTIFACTS_FULL
        known = set(cur)
        for p in want:
            if p in known or p == "/":
                continue
            if len(cur) >= ARTIFACTS_MAX:
                full = True
                break
            cur.append(p)
            known.add(p)
        target = os.path.join(self.dir, ARTIFACTS_FILE)
        tmp = "%s.%d.tmp" % (target, os.getpid())
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"paths": cur, "full": full} if full else {"paths": cur}, f)
            os.replace(tmp, target)
            _ARTIFACTS, _ARTIFACTS_FULL = tuple(cur), full
            return True
        except OSError:
            return False

    def add_latent(self, paths):
        """Remember scripts written from text that held a source marker (global, under the lock): the
        literal path and its realpath. Never evicts; at LATENT_MAX recording stops (False)."""
        global _LATENT, _LATENT_FULL
        want = []
        for p in paths:
            if isinstance(p, str) and p.startswith("/") and p != "/":
                want.append(os.path.normpath(p))
                try:
                    want.append(os.path.realpath(p))
                except (OSError, ValueError):
                    pass
        if not want:
            return True
        if os.environ.get("TAINT_FAIL_WRITES") in ("json", "all"):
            return False
        _LATENT = None
        cur = list(latent_paths())
        known = set(cur)
        for p in want:
            if p in known:
                continue
            if len(cur) >= LATENT_MAX:
                _LATENT, _LATENT_FULL = tuple(cur), True
                return False
            cur.append(p)
            known.add(p)
        target = os.path.join(self.dir, LATENT_FILE)
        tmp = "%s.%d.tmp" % (target, os.getpid())
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"paths": cur}, f)
            os.replace(tmp, target)
            _LATENT = tuple(cur)
            _LATENT_FULL = len(cur) >= LATENT_MAX
            return True
        except OSError:
            return False

    def update(self, **fields):
        """Best-effort bookkeeping write that keeps the taint fields as they are."""
        if self.path is None or self.unknown is not None:
            return False
        d = dict(self.data) if self.data else {"tainted": False}
        d.update(fields)
        return self._write(d)

    def clear(self, evidence_id=None):
        """A human message: clean record (pending calls and bookkeeping stay), then drop the flag.
        The evidence record that proved the human origin is consumed (it cannot clear a later taint)."""
        if self.path is None or self.unknown == "state-dir":
            return False
        d = (
            {
                k: v
                for k, v in self.data.items()
                if k not in ("source", "since", "count", "marked_at", "pending_human", "format_unknown_at")
            }
            if self.unknown is None
            else {}
        )
        if evidence_id:
            used = [e for e in (d.get("used_evidence") or []) if isinstance(e, str)]
            used.append(evidence_id)
            d["used_evidence"] = used[-tg_core.EVIDENCE_MAX :]
        d["tainted"] = False
        if not self._write(d):
            return False
        try:
            os.unlink(self.flag_path)
        except FileNotFoundError:
            pass
        except OSError:
            return False
        self.flag = False
        self.unknown = None
        return True


def log(session_id, event, tool, decision, reason):
    path = os.environ.get("TAINT_LOG") or tg_core.LOG_PATH
    line = "%s %s %s %s %s %s\n" % (
        tg_core.now_iso(),
        safe_token(session_id, 8),
        safe_token(event, 20),
        safe_token(tool, 80),
        decision,
        reason,
    )
    try:
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def switch_on():
    """The switch counts only as a root-owned regular file under /etc (G3)."""
    path = os.environ.get("TAINT_SWITCH") or tg_core.SWITCH_PATH
    if not path.startswith("/etc/") or ".." in path.split("/"):
        return False
    try:
        st = os.lstat(path)
    except OSError:
        return False
    import stat as stat_mod

    return stat_mod.S_ISREG(st.st_mode) and st.st_uid == 0
