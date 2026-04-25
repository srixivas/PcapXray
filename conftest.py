from pathlib import Path
import sys

_ROOT = Path(__file__).parent
_SOURCE_MODULE = _ROOT / "Source" / "Module"

if str(_SOURCE_MODULE) not in sys.path:
    sys.path.insert(0, str(_SOURCE_MODULE))

# Importable by test files that need the examples directory
EXAMPLES_DIR = _SOURCE_MODULE / "examples"
