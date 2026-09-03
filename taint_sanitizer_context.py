def safe_shell():

    import shlex
    import subprocess
    user = input()
    cleaned = shlex.quote(user)
    subprocess.run(cleaned, shell=True)

def not_safe_for_eval():
    # EXPECT PY.SEC.001
    import html
    user = input()
    cleaned = html.escape(user)
    eval(cleaned)
