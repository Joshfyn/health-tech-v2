"""The rule for what text a client may send: letters, digits and a little punctuation.

Anything else, and anything that reads as SQL, HTML or a link, is refused. This is defence in
depth: queries are parameterised and responses are JSON, so such text could not do harm
today, but it is never stored where some later consumer (a report, an email, an admin page)
might trust it.

Used twice with the same rule: by the payload guard middleware on every string in a request
body, and by the request models' field validators.
"""

import re
import unicodedata
from typing import Final

# Punctuation real names, addresses, emails, phone numbers, IDs and timestamps need:
# O'Brien, O’Brien, Jean-Luc, St. John, 12/3 Main St, Apt #4, +1 (555) 010-0000,
# sam_x+tag@example.com, 1990-05-15T00:00:00Z.
ALLOWED_PUNCTUATION: Final = frozenset(" '’-.,@_+():/#")

# Letters, combining marks (accents) and decimal digits, in any script.
_ALLOWED_CATEGORIES: Final = ("L", "M", "Nd")

_SQL_PATTERNS: Final = (
    r"--",  # comment
    r"\bunion\b.*\bselect\b",
    r"\bselect\b.*\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdelete\s+from\b",
    r"\bupdate\b.*\bset\b",
    r"\b(?:drop|truncate|alter|create)\s+(?:table|database|schema|index|view|user)\b",
    r"\b(?:exec|execute)\s+(?:xp_|sp_)",
    r"\bxp_cmdshell\b",
    r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
    r"\bwaitfor\s+delay\b",
    # ' OR 'a  /  ' AND 1
    r"'\s*(?:or|and)\s+['\w]",
)
_LINK_PATTERNS: Final = (
    r"\b[a-z][a-z0-9+.\-]*://",  # https://, ftp://, any scheme://
    r"\b(?:javascript|vbscript|data|file|mailto)\s*:",
    r"(?<![@.\w])www\.",  # www.example.com, but not user@www.example.com
)
_UNSAFE_PATTERN: Final = re.compile(
    "|".join(f"(?:{p})" for p in (*_SQL_PATTERNS, *_LINK_PATTERNS)),
    re.IGNORECASE | re.DOTALL,
)


def is_allowed_character(char: str) -> bool:
    """Report whether char may appear in client text."""
    return char in ALLOWED_PUNCTUATION or unicodedata.category(char).startswith(_ALLOWED_CATEGORIES)


def unsafe_reason(value: str) -> str | None:
    """Return why value is not safe text, or None if it is.

    The reason is for server logs only; it never goes to the client.
    """
    for char in value:
        if not is_allowed_character(char):
            # HTML (< > &), quotes, statement separators, control characters, symbols.
            return f"character U+{ord(char):04X} is not allowed"
    # Full-width and other compatibility forms read as their plain letters.
    if _UNSAFE_PATTERN.search(unicodedata.normalize("NFKC", value)):
        return "text reads as SQL or a link"
    return None
