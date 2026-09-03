"""Coverage for the PY.SEC.012 string-construction fallback.

The taint engine is intra-procedural, so when a path is assembled inside a
helper the untrusted source is in another frame and no path can be proven.
Reporting these at MEDIUM keeps the finding without overstating confidence.

The safe half must stay silent: os.path.join is the recommended practice and
a fully constant path has nothing to splice.

EXPECT PY.SEC.012
"""

import io
import os

BASE = "/var/data/"


# --- must be reported -------------------------------------------------------

def read_concat(name):
    return open(BASE + name).read()


def read_fstring(name):
    return open(f"/var/data/{name}").read()


def read_format(name):
    return open("/var/data/{}".format(name)).read()


def read_percent(name):
    return io.open("/var/data/%s" % name).read()


# --- must NOT be reported ---------------------------------------------------

def read_joined(name):
    # Joining is the correct practice; flagging it would bury the signal.
    return open(os.path.join(BASE, name)).read()


def read_constant():
    return open("/etc/hostname").read()


def read_concat_constant():
    return open(BASE + "fixed_name.txt").read()
