from pathlib import Path
import sys


def ensure_src_on_path(current_file: str) -> None:
    current = Path(current_file).resolve()

    for parent in [current.parent] + list(current.parents):
        if parent.name == "src":
            if str(parent) not in sys.path:
                sys.path.insert(0, str(parent))
            return

    raise RuntimeError("Could not locate 'src' directory for path setup.")