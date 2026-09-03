"""
Taint analysis demonstration.

Both functions below call eval(). A pattern-matching linter reports them
identically. SentinelLint does not, because it traces where the argument
came from:

  safe_eval_constant   -> LOW  confidence, the argument is a constant
  unsafe_eval_userdata -> HIGH confidence, with the full path from the
                          input() call on one line, through each
                          assignment, to the eval() that executes it.

That difference is the whole argument for parsing rather than matching text.
"""

LIMIT = eval("2 + 2")


def safe_eval_constant():
    """The argument never leaves the source file."""
    formula = "10 * 3"
    return eval(formula)


def unsafe_eval_userdata():
    """The argument originates from the user, four statements earlier."""
    raw = input("enter a formula: ")
    trimmed = raw.strip()
    prepared = "result = " + trimmed
    return eval(prepared)


def unsafe_shell_from_argv():
    """Command line argument reaches a shell."""
    import os
    import sys
    target = sys.argv[1]
    command = "ls -la " + target
    os.system(command)


def sanitized_is_not_reported():
    """int() removes the taint, so this must NOT be reported as HIGH."""
    import os
    raw = input("how many? ")
    count = int(raw)
    os.system("echo " + str(count))
