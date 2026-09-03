"""Print the environment needed to reproduce any external benchmark run."""
import platform
import sys
import sysconfig
from pathlib import Path

root = Path(__file__).resolve().parent.parent
print(f"SentinelLint root: {root}")
print(f"Python: {sys.version.split()[0]}")
print(f"Executable: {sys.executable}")
print(f"Platform: {platform.platform()}")
print(f"Machine: {platform.machine()}")
print(f"Stdlib: {sysconfig.get_paths().get('stdlib', '')}")
