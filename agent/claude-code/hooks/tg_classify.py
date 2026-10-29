"""Untrusted-source classification, write destinations and the tainted read-only policy."""
import os
import re
import tg_core
import tg_lexer
import tg_state


def path_source(path):
    """Fixed source code for a normalized absolute path, or None."""
    if tg_state.extra_path_source(path):
        return "extra-path"
    if path == "/var/log" or path.startswith("/var/log/"):
        if tg_core.LOCAL_ADMIN_LOGS.match(path):
            return None
        return "var-log"
    if path == tg_core.QUARANTINE_DIR or path.startswith(tg_core.QUARANTINE_DIR + "/"):
        return "quarantine"
    if path.startswith(tg_core.ATLAS_STATE + "/"):
        rest = path[len(tg_core.ATLAS_STATE) + 1:]
        if rest.startswith("events.jsonl"):
            return "atlas-events"
        if rest == "drift.log":
            return "atlas-drift"
    return is_artifact(path)


def is_artifact(path):
    """'artifact', 'artifact-registry-full' or None."""
    for a in tg_state.artifact_paths():
        if path == a or path.startswith(a.rstrip("/") + "/"):
            return "artifact"
    if tg_state._ARTIFACTS_FULL and any(path == r or path.startswith(r + "/") for r in tg_state.FULL_REGISTRY_ROOTS):
        return "artifact-registry-full"  # copies may exist that the registry could not record
    return None


def ancestor_source(path):
    """A directory that contains a source (e.g. Grep over /var or /)."""
    if path == "/":
        return "var-log"
    for root, code in (("/var/log", "var-log"), (tg_core.QUARANTINE_DIR, "quarantine"),
                       (tg_core.ATLAS_STATE, "atlas-events")) + tuple(
                           (r, "extra-path") for r in tg_state.config()["extra_untrusted_paths"]):
        if root.startswith(path.rstrip("/") + "/"):
            return code
    return None


def candidate_paths(path, cwd):
    if not isinstance(path, str) or not path:
        return []
    if "\x00" in path:
        return []
    base = cwd if isinstance(cwd, str) and cwd.startswith("/") else "/"
    p = os.path.normpath(os.path.join(base, os.path.expanduser(path)))
    out = [p]
    try:
        r = os.path.realpath(p)
        if r != p:
            out.append(r)
    except (OSError, ValueError):
        pass
    return out


def file_tool_source(tool, ti, cwd):
    paths = []
    if tool == "Read":
        paths = [ti.get("file_path")]
    elif tool == "Grep":
        paths = [ti.get("path") or cwd]
    elif tool == "Glob":
        base = ti.get("path") or cwd
        pat = ti.get("pattern")
        paths = [base]
        if isinstance(pat, str):
            # the static prefix of the pattern, joined to the base
            static = re.split(r"[*?\[{]", pat, maxsplit=1)[0]
            paths.append(os.path.join(base, static) if isinstance(base, str) else static)
    for raw in paths:
        for p in candidate_paths(raw, cwd):
            src = path_source(p)
            if src:
                return src
            if tool in ("Grep", "Glob"):
                src = ancestor_source(p)
                if src:
                    return src
    return None


PROGRAM_SOURCES = {"journalctl": "journalctl", "curl": "curl", "wget": "wget"}


SHELLS = frozenset({"bash", "sh", "dash", "zsh"})


PATH_EXEMPT_PROGRAMS = frozenset({"ls", "untrusted-export"})


ANCESTOR_EXEMPT = frozenset({"ls", "du", "df", "stat", "cd", "pwd"})


RAW_PATH_MARKERS = (
    (tg_core.Lazy(r"/var/log(?![\w.-])|/var/log/"), "var-log"),
    (tg_core.Lazy(re.escape(tg_core.QUARANTINE_DIR)), "quarantine"),
    (tg_core.Lazy(r"atlas-state/events\.jsonl|" + re.escape(tg_core.ATLAS_STATE) + r"/events\.jsonl"), "atlas-events"),
    (tg_core.Lazy(r"atlas-state/drift\.log|" + re.escape(tg_core.ATLAS_STATE) + r"/drift\.log"), "atlas-drift"),
)


RAW_PROGRAM_MARKERS = (
    (tg_core.Lazy(r"\bjournalctl\b"), "journalctl"),
    (tg_core.Lazy(r"\bcurl\b"), "curl"),
    (tg_core.Lazy(r"\bwget\b"), "wget"),
    (tg_core.Lazy(r"\bgh\s+(api|pr\s+view|issue\s+view)\b"), "gh"),
    (tg_core.Lazy(r"\bsystemctl\b[^;&|]*\bstatus\b"), "systemctl-status"),
)


def raw_bash_source(cmd):
    for root in tg_state.config()["extra_untrusted_paths"]:
        if root in cmd:
            return "extra-path"
    for rx, code in RAW_PROGRAM_MARKERS + RAW_PATH_MARKERS:
        if rx.search(cmd):
            if code == "var-log" and not _var_log_outside_local_logs(cmd):
                continue
            return code
    return None


def _var_log_outside_local_logs(cmd):
    for m in re.finditer(r"/var/log[^\s'\";|&<>()]*", cmd):
        if not tg_core.LOCAL_ADMIN_LOGS.match(os.path.normpath(m.group(0))):
            return True
    return False


def systemctl_status_tail(args):
    """`systemctl status` prints the unit's last journal lines (raw, attacker-controllable log text)
    unless the EFFECTIVE line count is 0: the last -n/--lines wins."""
    if "status" not in args:
        return False
    lines = "10"
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--") and long_opt(a, ("lines",)):
            if "=" in a:
                lines = a.split("=", 1)[1]
            elif i + 1 < len(args):
                lines = args[i + 1]
                i += 1
        elif a.startswith("-") and not a.startswith("--") and "n" in a[1:]:
            rest = a[a.index("n", 1) + 1:]
            if rest:
                lines = rest
            elif i + 1 < len(args):
                lines = args[i + 1]
                i += 1
        i += 1
    try:
        return int(lines) != 0
    except ValueError:
        return True


READERS = frozenset({
    "cat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "zcat", "zless", "less", "more", "awk",
    "gawk", "sed", "sort", "uniq", "cut", "tr", "wc", "jq", "diff", "strings", "od", "xxd", "hexdump",
    "base64", "tac", "nl", "paste", "join", "comm", "column", "fold", "rev", "iconv", "file",
    "sha256sum", "md5sum", "cp", "mv", "tee", "dd", "rsync", "scp", "install", "python3", "perl",
    "vim", "view", "nano", "bat", "tar", "gzip", "gunzip", "xz", "unxz", "bzip2", "bunzip2"})


WRAPPERS = frozenset({"sudo", "doas", "env", "nice", "nohup", "timeout", "stdbuf", "ionice",
                      "command", "exec", "time"})


WRAPPER_VALUE_OPTS = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-n", "-s",
                                "-k", "-c"})


GLOB_ROOTS = (("/var/log", "var-log"), (tg_core.QUARANTINE_DIR, "quarantine"),
              (tg_core.ATLAS_STATE + "/events.jsonl*", "atlas-events"), (tg_core.ATLAS_STATE + "/drift.log", "atlas-drift"))


WORDS_PER_SEGMENT_MAX = 64


def effective_program(words):
    """(index, basename) of the program after env assignments and wrappers such as sudo/timeout."""
    i = 0
    while i < len(words):
        w = words[i]
        b = os.path.basename(w)
        if "=" in w and not w.startswith("-") and "/" not in w.split("=", 1)[0]:
            i += 1
            continue
        if b in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in WRAPPER_VALUE_OPTS else 1
            if b == "timeout" and i < len(words):
                i += 1  # duration
            continue
        return i, b
    return None, None


def has_glob(word):
    return any(c in word.raw_unquoted() for c in "*?[")


def has_brace_expansion(word):
    u = word.raw_unquoted()
    return "{" in u and ("," in u or ".." in u)


def glob_source(pattern, cwd, prog):
    """Finding 7: a glob counts by the files Bash will open. A pattern that can reach a source root
    taints even if nothing matches now; existing matches (symlinks, artifacts) are checked too."""
    import fnmatch
    base = cwd if isinstance(cwd, str) and cwd.startswith("/") else "/"
    pat = os.path.normpath(os.path.join(base, os.path.expanduser(pattern)))
    parts = pat.strip("/").split("/")
    for root, code in GLOB_ROOTS + tuple((r, "extra-path") for r in tg_state.config()["extra_untrusted_paths"]):
        rparts = root.strip("/").split("/")
        k = min(len(parts), len(rparts))
        if k < len(rparts) and prog in ANCESTOR_EXEMPT:
            continue
        if all(fnmatch.fnmatchcase(rparts[i], parts[i]) or fnmatch.fnmatchcase(parts[i], rparts[i])
               for i in range(k)):
            return code
    import glob
    import itertools
    for m in itertools.islice(glob.iglob(pat), 200):
        for p in candidate_paths(m, cwd):
            src = path_source(p)
            if src:
                return src
    return None


DATA_PROGRAMS = frozenset({"echo", "printf", "cat", "tee"})


ARG_DATA_PROGRAMS = frozenset({"echo", "printf"})


PIPES = frozenset({"|", "|&"})


REDIRECT_OPS = frozenset({">", ">>", "1>", "2>", "1>>", "2>>", "&>", "&>>", ">|", "<", "0<", ">&", "1>&",
                          "2>&", "<&", "<>", "&>"})


def _code_runs_in(cmd):
    """Command or process substitution anywhere in the command: text may be executed or expanded."""
    return any(m in cmd for m in ("$(", "`", "<(", ">("))


def _flatten_substitutions(text):
    """Turn the insides of command/process substitutions into commands of their own."""
    for marker in ("$(", "`", "<(", ">(", ")"):
        text = text.replace(marker, " ; ")
    return text


def _dest_ok(path):
    """R5: a write destination that cannot be executed implicitly: a .md/.txt file that is not a symlink, has
    no execute bit and is not under .git or .claude (checked on the path and on its resolved parent)."""
    if not path.endswith((".md", ".txt")) or os.path.islink(path):
        return False
    real = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    for p in (path, real):
        if any(c in (".git", ".claude") for c in p.split("/")):
            return False
    try:
        if os.stat(path).st_mode & 0o111:
            return False
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def _dests_blocked(toks, cwd):
    """True when some write destination of the command fails _dest_ok (redirect targets, tee operands)."""
    for seg in tg_lexer.segments(toks):
        words = [v.text() for k, v in seg if k == "w"][:WORDS_PER_SEGMENT_MAX]
        pi, prog = effective_program(words)
        if pi is None:
            continue
        if any(not _dest_ok(d) for d in _seg_write_dests(seg, prog, words, pi, cwd)):
            return True
    return False


def _is_data_segment(seg, sep, prog, cmd_flat, has_dest=True):
    """Text that a simple command only writes: here-document bodies and here-strings of echo/printf/cat/tee
    and the arguments of echo/printf, when the output goes to a file or to nothing."""
    if prog not in DATA_PROGRAMS or cmd_flat or sep in PIPES:
        return False
    if prog in ("cat", "tee") and not has_dest:
        return False  # stdout of cat/tee is shown to the model: classify the text as base does
    return not any(k == "op" and v in ("(", ")") for k, v in seg)


def _seg_words(seg):
    """(Word, kind) for each word of a segment: 'redirect' after a redirect operator, 'herestring' after <<<,
    else 'arg'."""
    out, prev = [], None
    for k, v in seg:
        if k == "w":
            kind = "redirect" if prev in REDIRECT_OPS else "herestring" if prev == "<<<" else "arg"
            out.append((v, kind))
            prev = None
        else:
            prev = v
    return out


OVERRIDE_WORDS = frozenset({"alias", "unalias", "shopt", "enable", "eval", "builtin", "exec", "hash",
                            "command", "function", "source", "."})


INTERPRETER = tg_core.Lazy(r"^(python[0-9.]*|perl|ruby|node|php|awk|gawk|sed)$")


def _redefines(toks):
    """The command defines or changes what a command name means (function, alias, eval, ...): the data
    exemption cannot trust that echo is echo."""
    prev = None
    for kind, v in toks:
        if kind == "w":
            if v.text() in OVERRIDE_WORDS:
                return True
        elif v == ")" and prev == "(":
            return True  # name() { ...; }
        prev = v if kind == "op" else None
    return False


ALLOWED_PROGRAMS = frozenset({"cat", "echo", "printf", "tee", "true", ":", "git"})  # R1: the data exemption


READ_PROGRAMS = frozenset({"cat", "grep", "head", "tail", "less", "wc", "ls", "stat", "file", "diff",
                           "sha256sum", "git"})  # R2: commands that only read a latent script


GIT_R1 = frozenset({"add", "commit", "status", "diff", "log"})


GIT_R2 = frozenset({"status", "diff", "log", "show", "add", "commit"})


def _git_ok(words, subs):
    """git [-C <dir>]... <subcommand> with a subcommand from `subs`; no other option before it."""
    i = 1
    while i < len(words) and words[i] == "-C" and i + 1 < len(words):
        i += 2
    return i < len(words) and words[i] in subs


def _only_programs(toks, allowed, subs):
    """True if the first (unquoted) word of EVERY simple command is in `allowed`: no wrapper, no
    assignment, no path. An empty segment (redirection only, blank line) is fine."""
    for seg in tg_lexer.segments(toks):
        words = [v.text() for k, v in seg if k == "w"][:WORDS_PER_SEGMENT_MAX]
        if not words:
            continue
        if any(k == "op" and v in ("(", ")") for k, v in seg):
            return False
        first = words[0]
        if first not in allowed:
            return False
        if first == "git" and not _git_ok(words, subs):
            return False
    return True


def _mentions_latent(cmd, toks, cwd):
    """A latent script named in the command: raw text, an unquoted word (or part of one), or a word
    resolved against cwd."""
    paths = tg_state.latent_paths()
    if not paths:
        return False
    if any(p in cmd for p in paths):
        return True
    known = set(paths)
    for kind, v in toks or ():
        if kind == "w":
            t = v.text()
            if any(p in t for p in paths) or any(c in known for c in candidate_paths(t, cwd)):
                return True
    return False


def _seg_write_dests(seg, prog, words, pi, cwd):
    """Absolute paths a data segment writes: output redirections and tee operands."""
    out = []
    for i, (kind, v) in enumerate(seg):
        if kind == "op" and v in WRITE_REDIRECTS and i + 1 < len(seg) and seg[i + 1][0] == "w":
            t = seg[i + 1][1].text()
            if t != "/dev/null":
                out.append(_abs(t, cwd))
    if prog == "tee":
        out += [_abs(a, cwd) for a in positionals(words[pi + 1:]) if a != "-"]
    return out


def bash_source(cmd, cwd, depth=0, latent=None):
    """Best-effort classification of an honest command (the model is trusted before taint).
    `latent`: a list that receives the destinations of exempted data text containing a source marker.
    R2: a command that names a latent script and contains an executing word runs it (reading it does not taint)."""
    try:
        toks = tg_lexer.tokenize(cmd)
    except tg_core.ParseError:
        toks = None
    if _mentions_latent(cmd, toks, cwd):
        # R2: only plain readers may name a latent script
        if toks is None or _code_runs_in(cmd) or not _only_programs(toks, READ_PROGRAMS, GIT_R2):
            return "latent"
    found = []
    # The write-text data exemption is OFF by default; set TAINT_WRITE_TEXT_EXEMPTION=1 to enable it
    src = _classify(cmd, cwd, depth, found, os.environ.get("TAINT_WRITE_TEXT_EXEMPTION") == "1")
    if latent is not None:
        latent.extend(d for d, _ in found)
    return src


def _classify(cmd, cwd, depth, latent, exempt_ok):
    try:
        toks = tg_lexer.tokenize(cmd)
    except tg_core.ParseError:
        return raw_bash_source(cmd)
    cmd_flat = _code_runs_in(cmd) or _redefines(toks) or not _only_programs(toks, ALLOWED_PROGRAMS, GIT_R1) \
        or _dests_blocked(toks, cwd) or not exempt_ok  # R1, R5
    for seg, sep in tg_lexer.segments_with_sep(toks):
        pairs = _seg_words(seg)[:WORDS_PER_SEGMENT_MAX]
        wobjs = [w for w, _ in pairs]
        if not wobjs:
            continue
        words = [w.text() for w in wobjs]
        pi, prog = effective_program(words)
        data_seg = _is_data_segment(seg, sep, prog, cmd_flat,
                                    bool(_seg_write_dests(seg, prog, words, pi, cwd)) if pi is not None else False)
        data_seg, text_only = _data_words(pairs, words, pi, prog, seg, cwd, data_seg, latent)
        if not data_seg:
            for w in wobjs:
                if w.heredoc:  # executed or interpreted text (shells, interpreters, pipes): classify as commands
                    src = _classify(w.heredoc, cwd, depth, latent, exempt_ok)
                    if src:
                        return src
                    if _code_runs_in(w.heredoc):  # substitutions in the body run (unquoted delimiter)
                        src = _classify(_flatten_substitutions(w.heredoc), cwd, depth, latent, exempt_ok)
                        if src:
                            return src
        if prog == "untrusted-export":
            continue
        src = _segment_source(words, wobjs, pi, prog, text_only, cwd, depth, latent, exempt_ok)
        if src:
            return src
    return None


def _data_words(pairs, words, pi, prog, seg, cwd, data_seg, latent):
    text_only = set()
    if data_seg:
        for idx, (w, kind) in enumerate(pairs):
            if idx <= (pi or 0):
                continue
            if w.heredoc is not None or kind == "herestring" or (
                    prog in ARG_DATA_PROGRAMS and kind == "arg"):
                text_only.add(idx)
        texts = [pairs[i][0].heredoc if pairs[i][0].heredoc is not None else words[i] for i in text_only]
        marker = next((m for m in (raw_bash_source(t) for t in texts) if m), None)
        if marker:
            dests = _seg_write_dests(seg, prog, words, pi, cwd)
            if dests and tg_state.latent_full():
                data_seg, text_only = False, set()  # cannot remember the script: classify as today
            else:
                latent.extend((d, marker) for d in dests)
    return data_seg, text_only


def _program_source(words, text_only, cwd, depth, latent, exempt_ok):
    for idx, w in enumerate(words):
        if idx in text_only:
            continue
        b = os.path.basename(w)
        if b in PROGRAM_SOURCES:
            return PROGRAM_SOURCES[b]
        if b == "systemctl" and systemctl_status_tail(words[idx + 1:]):
            return "systemctl-status"
        if b == "gh" and len(words) > idx + 1:
            rest = words[idx + 1:idx + 3]
            if rest[0] == "api" or (rest[0] in ("pr", "issue") and "view" in rest):
                return "gh"
        if b in SHELLS and depth < 3 and "-c" in words[idx + 1:]:
            k = words.index("-c", idx + 1)
            if k + 1 < len(words):
                src = _classify(words[k + 1], cwd, depth + 1, latent, exempt_ok)
                if src:
                    return src
        if b == "xargs" or long_opt(w, ("files0-from", "files-from")):
            return "indirect-input"  # the files read are named by data the gate never sees
    return None


def _segment_source(words, wobjs, pi, prog, text_only, cwd, depth, latent, exempt_ok):
    src = _program_source(words, text_only, cwd, depth, latent, exempt_ok)
    if src:
        return src
    exempt = prog in PATH_EXEMPT_PROGRAMS
    for idx, wobj in enumerate(wobjs):
        if idx <= (pi or 0) or idx in text_only:
            continue
        w = wobj.text()
        if wobj.expands and _code_runs_in(w):
            # command or process substitution inside a word (also in double quotes): it runs
            src = _classify(_flatten_substitutions(w), cwd, depth, latent, exempt_ok)
            if src:
                return src
        if wobj.expands or has_brace_expansion(wobj):
            if prog in READERS:
                return "unresolved-path"
            continue
        if exempt:
            continue
        if has_glob(wobj):
            src = glob_source(w, cwd, prog)
            if src:
                return src
            continue
        for p in _word_paths(w, cwd):
            src = path_source(p)
            if src:
                return src
            if prog not in ANCESTOR_EXEMPT and w.startswith("/"):
                src = ancestor_source(p)
                if src:
                    return src
    if isinstance(cwd, str) and not exempt:
        src = path_source(os.path.normpath(cwd))
        if src:
            return src
    return None


def _word_paths(w, cwd):
    if not w or w.startswith("-") and "=" not in w:
        return []
    out = []
    if "=" in w:
        out += candidate_paths(w.split("=", 1)[1], cwd)  # --opt=PATH, if=PATH, of=PATH
        if w.startswith("-"):
            return out
    return out + candidate_paths(w, cwd)


WRITE_REDIRECTS = frozenset({">", ">>", "1>", "2>", "1>>", "2>>", "&>", "&>>", ">|"})


COPY_PROGRAMS = frozenset({"cp", "mv", "install", "rsync", "scp"})


def _abs(path, cwd):
    base = cwd if isinstance(cwd, str) and cwd.startswith("/") else "/"
    return os.path.normpath(os.path.join(base, os.path.expanduser(path)))


def write_targets(cmd, cwd):
    """Where a command that read untrusted data writes: redirections, tee, cp/mv-like
    destinations, dd of=, sort -o. Best effort; unknown writers (scripts) are not covered."""
    try:
        toks = tg_lexer.tokenize(cmd)
    except tg_core.ParseError:
        return []
    out = []
    cmd_flat = _code_runs_in(cmd) or _redefines(toks) or not _only_programs(toks, ALLOWED_PROGRAMS, GIT_R1) \
        or _dests_blocked(toks, cwd)
    for seg, sep in tg_lexer.segments_with_sep(toks):
        words, bodies, redirects = _write_segment(seg, cwd)
        out += redirects
        pi, prog = effective_program(words)
        if pi is None:
            continue
        if bodies and not _is_data_segment(seg, sep, prog, cmd_flat, bool(_seg_write_dests(seg, prog, words, pi, cwd))):
            for body in bodies:  # executed or interpreted text: its redirections write too
                out += write_targets(body, cwd)
        out += _program_targets(prog, words[pi + 1:], cwd)
    return [x for x in out if x != "/dev/null"]


def _write_segment(seg, cwd):
    out = []
    words, i = [], 0
    bodies = []
    while i < len(seg):
        kind, v = seg[i]
        if kind == "op":
            if i + 1 < len(seg) and seg[i + 1][0] == "w":
                t = seg[i + 1][1].text()
                if seg[i + 1][1].heredoc:
                    bodies.append(seg[i + 1][1].heredoc)
                if (v in WRITE_REDIRECTS or (v in (">&", "&>") and not t.isdigit())) \
                        and t != "/dev/null":
                    out.append(_abs(t, cwd))
                i += 2
                continue
            i += 1
            continue
        words.append(v.text())
        if v.heredoc:
            bodies.append(v.heredoc)
        i += 1
    return words, bodies, out


def _program_targets(prog, args, cwd):
    out = []
    pos = positionals(args)
    if prog == "tee":
        out += [_abs(a, cwd) for a in pos if a != "-"]
    elif prog in COPY_PROGRAMS:
        out += _copy_targets(args, pos, cwd)
    elif prog == "dd":
        out += [_abs(a[3:], cwd) for a in args if a.startswith("of=")]
    elif prog == "sort":
        for j, a in enumerate(args):
            if a == "-o" and j + 1 < len(args):
                out.append(_abs(args[j + 1], cwd))
            elif a.startswith("--output="):
                out.append(_abs(a.split("=", 1)[1], cwd))
            elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                out.append(_abs(a[2:], cwd))
    return out


def _copy_targets(args, pos, cwd):
    out = []
    tdir = None
    for j, a in enumerate(args):
        if a in ("-t", "--target-directory") and j + 1 < len(args):
            tdir = args[j + 1]
        elif a.startswith("--target-directory="):
            tdir = a.split("=", 1)[1]
    if tdir is not None:
        srcs = [a for a in pos if a != tdir]
    elif len(pos) >= 2:
        tdir, srcs = pos[-1], pos[:-1]
    else:
        return []
    dest = _abs(tdir, cwd)
    if tdir.endswith("/") or os.path.isdir(dest) or len(srcs) > 1 or "-t" in args \
            or any(a.startswith("--target-directory") for a in args):
        out += [os.path.join(dest, os.path.basename(x.rstrip("/"))) for x in srcs]
    else:
        out.append(dest)
    return out


def tool_source(tool, ti, cwd, latent=None):
    if tool in tg_core.TOOL_SOURCES:
        return tg_core.TOOL_SOURCES[tool]
    if tool.startswith(tg_core.BROWSER_PREFIXES):
        return "browser"
    if tg_core.CONNECTOR_READ.match(tool):
        return "connector"
    if tg_state.extra_tool_source(tool):
        return "extra-tool"
    if tool in ("Read", "Grep", "Glob"):
        return file_tool_source(tool, ti, cwd)
    if tool in ("Bash", "Monitor"):
        cmd = ti.get("command")
        if isinstance(cmd, str):
            if tool == "Monitor" and cmd.strip() in tg_state.monitor_commands():
                return None  # the Atlas sensor prints fixed identifiers for every sensor outside bus.TRUSTED_TEXT_SENSORS
            return bash_source(cmd, cwd, latent=latent)  # a monitored command's events reach the model
    return None


SIMPLE_READERS = frozenset({
    "cat", "head", "tail", "grep", "egrep", "wc", "ls", "stat", "uptime", "df", "du", "free", "ps",
    "id", "whoami", "uname", "jq", "cut", "tr", "diff", "sha256sum", "last",
})


CHECKED = frozenset({"sort", "uniq", "awk", "sed", "date", "file", "hostname", "ss",
                     "systemctl", "journalctl", "dpkg", "apt", "crontab",
                     "ssh-keygen", "docker", "getent"})


PROGRAM_NAME = tg_core.Lazy(r"^[a-z][a-z0-9-]*$")


RAW_FORBIDDEN = ("`", "$(", "${", "<(", ">(", "$'", '$"', "\x00")


MAX_COMMAND = 8000


def short_cluster(arg, letters):
    """True if arg is a short-option cluster (-abc) containing any of `letters`."""
    return (arg.startswith("-") and not arg.startswith("--") and len(arg) > 1
            and any(ch in arg[1:] for ch in letters))


def positionals(args):
    out, rest = [], False
    for a in args:
        if rest or not a.startswith("-") or a == "-":
            out.append(a)
        elif a == "--":
            rest = True
    return out


def long_opt(arg, names):
    """True if arg is a GNU long option that is, or abbreviates, one of `names`.

    getopt_long accepts any unambiguous prefix (`--out` means `--output`), so a startswith test on
    the full name is not enough."""
    if not arg.startswith("--") or arg == "--":
        return False
    name = arg[2:].split("=", 1)[0]
    return bool(name) and any(n.startswith(name) or name.startswith(n) for n in names)


def check_sort(args):
    for a in args:
        if a == "--":
            continue
        if long_opt(a, ("output", "compress-program")) or short_cluster(a, "o"):
            return False
    return True


def check_uniq(args):
    return len(positionals(args)) <= 1


AWK_OPT = tg_core.Lazy(r"^(-F.*|-v.+|--)$")


def check_awk(args):
    expect_value = False
    for a in args:
        if expect_value:
            expect_value = False
        elif a in ("-F", "-v"):
            expect_value = True
        elif a.startswith("-") and a != "-" and not AWK_OPT.match(a):
            return False
        prog = a.replace("||", "").replace(">=", "")
        # pipes and redirection to commands/files, gawk extensions, system(), network special files
        if "|" in prog or ">" in prog or "@" in a or "system" in a or "/inet" in a:
            return False
    return not expect_value


SED_ADDR = r"(?:\d+(?:~\d+)?|\$|/(?:[^/\\\n]|\\.)*/I?)"


SED_RANGE = SED_ADDR + r"(?:\s*,\s*(?:" + SED_ADDR + r"|[+~]\d+))?"


SED_CMD = r"(?:[pdqQ=lnN]|s/(?:[^/\\\n]|\\.)*/(?:[^/\\\n]|\\.)*/[gpiI0-9]*)"


SED_ONE = r"(?:" + SED_RANGE + r")?\s*(?:!\s*)?" + SED_CMD


SED_SCRIPT = tg_core.Lazy(r"\s*" + SED_ONE + r"(?:\s*;\s*" + SED_ONE + r")*\s*(?:;\s*)?")


SED_SCRIPT_MAX = 1000


SED_LONG = frozenset({"--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered",
                      "--null-data", "--posix", "--debug", "--sandbox"})


def check_sed(args):
    quiet = False
    scripts, files = [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression"):
            if i + 1 >= len(args):
                return False
            scripts.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
        elif a in ("--quiet", "--silent"):
            quiet = True
        elif a in SED_LONG:
            pass
        elif a.startswith("--"):
            return False
        elif a.startswith("-") and len(a) > 1:
            if not re.fullmatch(r"-[nErsuz]+", a):
                return False
            quiet = quiet or "n" in a
        else:
            files.append(a)
        i += 1
    if not scripts:
        if not files:
            return False
        scripts.append(files.pop(0))
    return quiet and all(len(s) <= SED_SCRIPT_MAX and SED_SCRIPT.fullmatch(s) for s in scripts)


def check_date(args):
    return not any(long_opt(a, ("set",)) or short_cluster(a, "s") for a in args)


def check_file(args):
    return not any(long_opt(a, ("compile",)) or short_cluster(a, "C") for a in args)


def check_hostname(args):
    if positionals(args):
        return False
    return not any(long_opt(a, ("file", "boot")) or short_cluster(a, "bF") for a in args)


def check_ss(args):
    return not any(long_opt(a, ("kill", "diag")) or short_cluster(a, "KD") for a in args)


SYSTEMCTL_VERBS = frozenset({"status", "is-active", "is-enabled", "is-failed", "list-timers",
                             "list-units", "show"})


def check_systemctl(args):
    # The verb must come first: options before it may take a value (`-t status restart x`).
    if not args or args[0] not in SYSTEMCTL_VERBS:
        return False
    return not any(long_opt(a, ("host", "machine")) or short_cluster(a, "HM") for a in args)


JOURNALCTL_VALUE_SHORT = {"-u": None, "-t": None, "-S": None, "-U": None, "-p": None, "-g": None,
                          "-o": "output"}


JOURNALCTL_VALUE_LONG = {"--unit": None, "--identifier": None, "--since": None, "--until": None,
                         "--priority": None, "--grep": None, "--output-fields": None,
                         "--output": "output"}


JOURNALCTL_FLAGS = frozenset({"--no-pager", "-k", "--dmesg", "-r", "--reverse", "-b", "--boot",
                              "-n", "--lines", "-q", "--quiet", "-x", "--catalog", "--utc",
                              "--no-hostname", "-a", "--all"})


JOURNALCTL_OUTPUTS = frozenset({"short-iso", "cat", "json", "short", "short-precise"})


JOURNAL_MATCH = tg_core.Lazy(r"[A-Z_][A-Z0-9_]*=[^\x00-\x1f]*|\+")


def check_journalctl(args):
    """Positive allowlist of local reading options. Everything else - remote
    (-H/--host, -M/--machine), other journals (-D, --file, --root, --image), follow (-f),
    maintenance (--vacuum*, --rotate, ...), abbreviations - is denied."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in JOURNALCTL_VALUE_SHORT or a in JOURNALCTL_VALUE_LONG:
            if i + 1 >= len(args):
                return False
            kind = JOURNALCTL_VALUE_SHORT.get(a) or JOURNALCTL_VALUE_LONG.get(a)
            if kind == "output" and args[i + 1] not in JOURNALCTL_OUTPUTS:
                return False
            i += 2
            continue
        if a.startswith("--") and "=" in a:
            name, value = a.split("=", 1)
            if name in ("--lines", "--boot"):
                if not re.fullmatch(r"-?\d{1,7}", value):
                    return False
            elif name not in JOURNALCTL_VALUE_LONG:
                return False
            elif JOURNALCTL_VALUE_LONG[name] == "output" and value not in JOURNALCTL_OUTPUTS:
                return False
        elif a in ("-n", "--lines", "-b", "--boot"):
            if i + 1 < len(args) and re.fullmatch(r"-?\d{1,7}", args[i + 1]):
                i += 1  # optional numeric value
        elif re.fullmatch(r"-[nb]-?\d{1,7}", a):
            pass
        elif a.startswith("-") and len(a) > 2 and a[:2] in JOURNALCTL_VALUE_SHORT:
            if JOURNALCTL_VALUE_SHORT[a[:2]] == "output" and a[2:] not in JOURNALCTL_OUTPUTS:
                return False
        elif a in JOURNALCTL_FLAGS:
            pass
        elif not a.startswith("-") and JOURNAL_MATCH.fullmatch(a):
            pass  # journal field match such as _SYSTEMD_UNIT=ssh.service
        else:
            return False
        i += 1
    return True


GETENT_LOCAL = frozenset({"passwd", "group", "shadow", "gshadow", "shells"})


def check_getent(args):
    # hosts/ahosts/services... resolve through DNS: a lookup of "<secret>.evil.example" exfiltrates.
    pos = positionals(args)
    return bool(pos) and pos[0] in GETENT_LOCAL and all(not a.startswith("-") for a in args)


DPKG_READ = frozenset({"-l", "--list", "-s", "--status", "-L", "--listfiles", "-S", "--search",
                       "-V", "--verify", "-p", "--print-avail", "--get-selections"})


def check_dpkg(args):
    opts = [a for a in args if a.startswith("-")]
    return bool(opts) and all(a in DPKG_READ for a in opts)


APT_LIST_OPTS = frozenset({"--installed", "--upgradable", "--manual-installed", "-a",
                           "--all-versions", "-q", "-qq"})


def check_apt(args):
    if args[:1] != ["list"]:
        return False
    return all(a in APT_LIST_OPTS for a in args[1:] if a.startswith("-"))


def check_crontab(args):
    if args == ["-l"]:
        return True
    if len(args) == 3 and args[0] == "-u" and args[2] == "-l":
        return not args[1].startswith("-")
    if len(args) == 3 and args[0] == "-l" and args[1] == "-u":
        return not args[2].startswith("-")
    return False


def check_ssh_keygen(args):
    listed = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-l", "-v"):
            listed = listed or a == "-l"
        elif a in ("-f", "-lf", "-E"):
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                return False
            if a == "-E" and args[i + 1] not in ("md5", "sha256"):
                return False
            listed = listed or a == "-lf"
            i += 1
        else:
            return False
        i += 1
    return listed


def check_docker(args):
    return args[:1] == ["ps"]


CHECKERS = {
    "sort": check_sort, "uniq": check_uniq, "awk": check_awk, "sed": check_sed,
    "date": check_date, "file": check_file, "hostname": check_hostname, "ss": check_ss,
    "systemctl": check_systemctl, "journalctl": check_journalctl,
    "dpkg": check_dpkg, "apt": check_apt, "crontab": check_crontab,
    "ssh-keygen": check_ssh_keygen, "docker": check_docker, "getent": check_getent,
}


def redirect_ok(op, target):
    if op in (">", "1>", "2>", "&>"):
        return target == "/dev/null"
    if op in (">&", "1>&", "2>&"):
        return target in ("1", "2")
    if op in ("<", "0<"):
        # bash opens /dev/tcp/HOST/PORT and /dev/udp/... itself: a network connection (and a DNS
        # lookup of an arbitrary name) from a "read".
        return not target.startswith("/dev/")
    return False


def segment_allowed(seg):
    if not seg:
        return False
    words = []
    i = 0
    while i < len(seg):
        kind, v = seg[i]
        if kind == "op":
            if v in ("(", ")") or i + 1 >= len(seg) or seg[i + 1][0] != "w":
                return False
            target = seg[i + 1][1]
            if any(ch in target.raw_unquoted() for ch in "{}$*?[]~"):
                return False
            if not redirect_ok(v, target.text()):
                return False
            i += 2
            continue
        words.append(v)
        i += 1
    if not words:
        return False
    for w in words:
        if any(ch in w.raw_unquoted() for ch in "{}$*?[]"):
            return False  # brace/parameter expansion and globs can turn a word into an option
        if w.first_unquoted and w.first_unquoted in "#~":
            return False  # comment, tilde expansion
    prog_word = words[0]
    prog = prog_word.text()
    if prog_word.raw_unquoted() != prog or not PROGRAM_NAME.match(prog):
        return False
    args = [w.text() for w in words[1:]]
    if any(long_opt(a, ("files0-from",)) for a in args):
        return False  # an input list names files the gate never sees
    if prog in SIMPLE_READERS:
        return True
    if prog in CHECKED:
        return CHECKERS[prog](args)
    return False


def bash_allowed(cmd):
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > MAX_COMMAND:
        return False
    if any(f in cmd for f in RAW_FORBIDDEN) or "\n" in cmd or "\r" in cmd:
        return False
    try:
        toks = tg_lexer.tokenize(cmd)
    except tg_core.ParseError:
        return False
    for kind, v in toks:
        if kind == "op" and v not in tg_lexer.SEPARATORS and v not in (
                ">", "1>", "2>", "&>", ">&", "1>&", "2>&", "<", "0<"):
            return False
    return all(segment_allowed(seg) for seg in tg_lexer.segments(toks))


def tainted_allows(tool, ti):
    if tool in tg_core.TAINTED_TOOL_ALLOW:
        return True
    if tool == "Agent":
        return ti.get("subagent_type") in ("log-reader", "atlas-resident:log-reader")
    if tool == "Monitor":
        cmd = ti.get("command")
        return isinstance(cmd, str) and cmd.strip() in tg_state.monitor_commands()
    if tool == "Bash":
        return bash_allowed(ti.get("command"))
    return False

