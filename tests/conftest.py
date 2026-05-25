import sys
from pathlib import Path

# Ensure repository root is on sys.path so tests can import top-level modules.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
