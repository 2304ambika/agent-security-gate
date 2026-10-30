"""Deterministic text features for instruction-like content (inputs to learned rules).

The model is not involved: each feature is a fixed word-class regex. What gets *learned*
(rule_induction.py) is which conjunctions of these classes mark untrusted text as an
instruction. Rules over word classes can transfer to phrasings never seen in training,
which verbatim snippets cannot.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from .session import _EMAIL, _HOST, _PATH, _URL, _norm_email

_F = re.I
_CLASSES: dict[str, re.Pattern[str]] = {
    "addresses_agent": re.compile(r"\b(assistant|agents?|ai|bot|model|llm|copilot|helper|automated \w+|system)\b", _F),
    "directive_modal": re.compile(
        r"\b(please|kindly|must|should|need(?:s)? to|required to|make sure|be sure|remember to|"
        r"don'?t forget|has to|ensure|could you|can you)\b", _F),
    "next_step": re.compile(
        r"\b(also|then|afterwards?|once (?:you|done|finished)|when (?:you(?:'re| are) )?(?:done|finished)|"
        r"before (?:you|finishing|closing|completion)|prior to|final step|last stage|follow-?up|next step|"
        r"additionally|as well|one more thing|when you have a moment)\b", _F),
    "effect_verb": re.compile(
        r"\b(send|forward|email|mail|upload|post|share|copy|cc|bcc|write|append|save|store|persist|attach|"
        r"submit|publish|transmit|relay|deliver|hand|pass|load|invoke|run|execute|register)\b", _F),
    "data_object": re.compile(r"\b(summary|contents?|report|findings|results|credentials?|keys?|notes|data|figures)\b", _F),
    "override": re.compile(r"\b(ignore|disregard|instead|override|forget|new instructions?|supersede)\b", _F),
    "secrecy": re.compile(
        r"\b(silently|quietly|without (?:telling|mentioning|notifying|informing)|do not (?:tell|mention|inform)|"
        r"don'?t (?:tell|mention)|no need to (?:tell|inform|mention)|keep (?:this|it) (?:private|confidential|secret))\b", _F),
    "authority": re.compile(
        r"\b(compliance|policy|mandatory|administrator|admin|security team|approved|authorized|required by|"
        r"per (?:the )?(?:policy|ticket|rule)|ticket|urgent|immediately|priority)\b", _F),
}
FEATURES = tuple(_CLASSES) + ("foreign_target",)

_DEOBF = (
    (re.compile(r"\s*[\[\(\{]\s*at\s*[\]\)\}]\s*", _F), "@"),
    (re.compile(r"\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*", _F), "."),
    (re.compile(r"\s+at\s+(?=[\w-]+\s+(?:dot|\.)\s+)", _F), "@"),
    (re.compile(r"\s+dot\s+", _F), "."),
)


def deobfuscate(text: str) -> str:
    for pat, rep in _DEOBF:
        text = pat.sub(rep, text)
    return text


_RELPATH = re.compile(r"(?<![\w@:/.-])[\w.-]+(?:/[\w.-]+)+(?![\w@:/-])")  # a/b/c style paths (not URLs)


_FILE = re.compile(r"(?<![\w./@-])[\w-]+\.(?:md|sh|py|txt|json|ya?ml|cfg|conf|ini|toml|js|ts|pem|key|sql|csv)(?![\w/@-])", _F)


def _idents(text: str) -> set[str]:
    t = unquote(deobfuscate(text))
    out = {m.group(0).rstrip(".,;)").lower() for m in _URL.finditer(t)}
    out |= {_norm_email(m.group(0)) for m in _EMAIL.finditer(t)}
    out |= {m.group(0).lower() for m in _HOST.finditer(t)}
    out |= {m.group(0).lower() for m in _PATH.finditer(t)}
    bare = _URL.sub(" ", t)
    out |= {m.group(0).rstrip(".,;)").lower() for m in _RELPATH.finditer(bare)}
    out |= {m.group(0).lower() for m in _FILE.finditer(bare)}
    return out


def foreign_identifiers(text: str, task: str) -> set[str]:
    """Identifiers in untrusted text that the user's own task does not name."""
    task_ids = _idents(task)  # exact match only: a substring test lets "v@example.com" ride on "dev@example.com"
    return {i for i in _idents(text) if i not in task_ids}


_ENVELOPE = re.compile(r"^\[from [\w-]+\]\s*")  # added by the typed handoff, not content


_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n|\s{2,}|<!--|-->|\[\s?[x ]?\s?\]")


def extract(text: str, task: str = "") -> list[frozenset[str]]:
    """Feature set per sentence-like segment. Rules fire only when ONE segment has all their features,
    so a long benign document that merely contains the word classes somewhere does not match."""
    text = _ENVELOPE.sub("", text)
    out = []
    for seg in _SPLIT.split(text):
        if not seg.strip():
            continue
        feats = {name for name, pat in _CLASSES.items() if pat.search(seg)}
        if foreign_identifiers(seg, task):
            feats.add("foreign_target")
        if feats:
            out.append(frozenset(feats))
    return out


def fires(segments: list[frozenset[str]], rule: tuple[str, ...]) -> bool:
    return any(seg.issuperset(rule) for seg in segments)


# Header-bound delegation: a task such as "reply to the sender" lets the user authorize an identifier that
# the untrusted content supplies in a header line, and only there (a body line cannot name a recipient).
_DELEGATES = {
    "send_email": re.compile(r"\b(reply|respond|sender|author|requester)\b", _F),
    "http_fetch": re.compile(r"\b(follow|links?|references?|citations?)\b", _F),
}
_HEADER = re.compile(r"(?im)^(?:from|reply-to|author|reference):[ \t]*(.+)$")


def header_ids(ctx: str) -> set[str]:
    return {i for m in _HEADER.finditer(_ENVELOPE.sub("", ctx)) for i in _idents(m.group(1))}


def ungrounded(value: str, task: str, ctx: str, tool: str) -> set[str]:
    """Identifiers in an effect argument that neither the task nor a delegated header supplies."""
    bad = foreign_identifiers(value, task)
    if bad and (pat := _DELEGATES.get(tool)) and pat.search(task):
        bad -= header_ids(ctx)
    return bad


REDACTED = "[link removed]"


def redact_ungrounded(value: str, task: str, ctx: str, tool: str) -> tuple[str, int]:
    """Neutralize instead of block: replace URLs / e-mails / bare hosts in free text that neither the task nor a
    delegated header supplies. Scans a de-obfuscated copy, so `x [at] y [dot] com` cannot hide a target."""
    text = deobfuscate(value)
    ok = _idents(task) | (header_ids(ctx) if (pat := _DELEGATES.get(tool)) and pat.search(task) else set())
    spans: list[tuple[int, int]] = []
    # a bare host with a path (example.com/verify) is a URL, not just a host the task happens to name
    host_path = re.compile(_HOST.pattern + r"(?:/[^\s\"'<>)\]]*)?", _F)
    hp = lambda t: ("https://" + t.rstrip(".,;)").lower()) if "/" in t else t.lower()  # noqa: E731
    for rx, norm in ((_URL, lambda t: t.rstrip(".,;)").lower()), (_EMAIL, _norm_email), (host_path, hp)):
        for m in rx.finditer(text):
            if not any(a <= m.start() < b for a, b in spans) and norm(m.group(0)) not in ok:
                spans.append((m.start(), m.end()))
    for a, b in sorted(spans, reverse=True):
        text = text[:a] + REDACTED + text[b:]
    return text, len(spans)
