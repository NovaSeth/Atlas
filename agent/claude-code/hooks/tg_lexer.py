"""Shell words and operators, including quoted text, substitutions and heredocs."""
import re
import tg_core


SEPARATORS = frozenset({";", "&", "&&", "||", "|", "|&"})


OPERATORS = ("&>>", "<<<", "&&", "||", "|&", ";;", "&>", ">>", ">|", "<<", "<>", ">&", "<&",
             "|", "&", ";", "<", ">", "(", ")")


class Word:
    __slots__ = ("value", "unquoted", "first_unquoted", "expands", "heredoc")

    def __init__(self):
        self.heredoc = None  # body text when this word is a here-document delimiter
        self.value = []
        self.unquoted = []  # characters that bash would still interpret (globs, braces, $)
        self.first_unquoted = None
        self.expands = False  # parameter/command expansion, unquoted or inside double quotes

    def add(self, text, quoted):
        if not quoted:
            if "$" in text or "`" in text:
                self.expands = True
            if not self.value and self.first_unquoted is None and text:
                self.first_unquoted = text[0]
            self.unquoted.append(text)
        elif not self.value and self.first_unquoted is None:
            self.first_unquoted = ""
        self.value.append(text)

    def text(self):
        return "".join(self.value)

    def raw_unquoted(self):
        return "".join(self.unquoted)


def tokenize(s):
    """Split a bash command into ('w', Word) and ('op', str) tokens. Raises ParseError."""
    toks = []
    word = None
    line_start = 0  # index in toks where the current logical line begins
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            if word is not None:
                toks.append(("w", word))
                word = None
            i += 1
            continue
        if c in "\n\r":
            if word is not None:
                toks.append(("w", word))
                word = None
            toks.append(("op", "\n"))
            i = _read_heredocs(s, i + 1, toks, line_start) if c == "\n" else i + 1
            line_start = len(toks)
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise tg_core.ParseError("quote")
            word = word or Word()
            word.add(s[i + 1:j], True)
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            part = []
            dq_expands = False
            while True:
                if j >= n:
                    raise tg_core.ParseError("dquote")
                d = s[j]
                if d == "\\" and j + 1 < n and s[j + 1] in '"\\$`\n':
                    part.append(s[j + 1])
                    j += 2
                    continue
                if d == '"':
                    break
                if d in "$`":
                    dq_expands = True
                part.append(d)
                j += 1
            word = word or Word()
            word.add("".join(part), True)
            word.expands = word.expands or dq_expands
            i = j + 1
            continue
        if c == "\\":
            if i + 1 >= n:
                raise tg_core.ParseError("escape")
            word = word or Word()
            word.add(s[i + 1], True)
            i += 2
            continue
        if c in "|&;<>()":
            fd = ""
            if word is not None:
                t = word.text()
                if c in "<>" and t.isdigit() and word.raw_unquoted() == t:
                    fd = t
                else:
                    toks.append(("w", word))
                word = None
            for op in OPERATORS:
                if s.startswith(op, i):
                    toks.append(("op", fd + op))
                    i += len(op)
                    break
            continue
        word = word or Word()
        word.add(c, False)
        i += 1
    if word is not None:
        toks.append(("w", word))
    return toks


def _read_heredocs(s, pos, toks, line_start):
    """At a newline (s[pos-1]) after toks[line_start:]: read the bodies of the here-documents opened on
    that line (`<<`, `<<-` followed by a delimiter word) and store each on its delimiter Word. Returns the
    position after the last body. A body is data until the delimiter line; it is not tokenized."""
    n = len(s)
    j = line_start
    while j < len(toks) - 1:
        kind, v = toks[j]
        if kind == "op" and re.fullmatch(r"\d*<<", v) and toks[j + 1][0] == "w":
            delim_word = toks[j + 1][1]
            delim = delim_word.text()
            lines = []
            found = False
            while pos < n:
                e = s.find("\n", pos)
                line = s[pos:] if e < 0 else s[pos:e]
                pos = n if e < 0 else e + 1
                if line == delim or (delim.startswith("-") and line.lstrip("\t") == delim[1:]):  # <<-
                    found = True
                    break
                lines.append(line)
            delim_word.heredoc = "\n".join(lines)
            if not found:
                pos = n
        j += 1
    return pos


def segments(toks):
    """Simple commands: lists of tokens between separators (newline counts as a separator)."""
    return [seg for seg, _ in segments_with_sep(toks)]


def segments_with_sep(toks):
    """(tokens of a simple command, separator that follows it or None at the end)."""
    segs, cur = [], []
    for kind, v in toks:
        if kind == "op" and (v in SEPARATORS or v == "\n"):
            segs.append((cur, v))
            cur = []
        else:
            cur.append((kind, v))
    segs.append((cur, None))
    return segs


def words_of(seg):
    return [v.text() for k, v in seg if k == "w"]

