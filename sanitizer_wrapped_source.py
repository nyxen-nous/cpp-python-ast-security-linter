"""Regression guard: a sanitizer wrapping a source directly.

`_source_of` walks the whole expression, so for

    user_id = int(request.args.get('id'))

it matches the *inner* source. Before the fix, that returned early and the
sanitizer branch never ran, so the variable was marked tainted and the sink
was reported at HIGH confidence with a full evidence path — through a value
that had been sanitized. This is a common Flask/Django shape, so the false
positive would have shown up on real code.

The two-step form (`u = source()` then `c = int(u)`) was always handled
correctly; both forms must now agree.

Only the genuinely unsanitized call may be reported, and the file as a whole
must produce no traced taint path for the sanitized cases.

EXPECT PY.SEC.005
"""

import os

from flask import request


def one_step_sanitized():
    # int() cannot carry shell metacharacters: no taint path.
    cleaned = int(request.args.get("id"))
    os.system(cleaned)


def two_step_sanitized():
    # The same value, sanitized in two steps: must agree with the above.
    raw = request.args.get("id")
    cleaned = int(raw)
    os.system(cleaned)


def genuinely_tainted():
    # No sanitizer anywhere: this one is the EXPECT above.
    raw = request.args.get("cmd")
    os.system(raw)
