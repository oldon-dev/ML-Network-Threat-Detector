from pathlib import Path
import json


MANIFEST_DIR = Path("data/processed/manifests")


def discover_manifests() -> list[dict]:
    if not MANIFEST_DIR.exists():
        raise FileNotFoundError(f"Manifest directory not found: {MANIFEST_DIR}")

    manifests = []
    for path in sorted(MANIFEST_DIR.glob("*.json")):
        with open(path, "r", encoding="utf-8") as f:
            manifests.append(json.load(f))

    if not manifests:
        raise FileNotFoundError(f"No manifest files found in: {MANIFEST_DIR}")

    return manifests


def select_manifests(enabled_datasets: list[str] | None = None) -> list[dict]:
    manifests = discover_manifests()

    if enabled_datasets is None:
        return manifests

    selected = [m for m in manifests if m["dataset_name"] in enabled_datasets]
    missing = sorted(set(enabled_datasets) - {m["dataset_name"] for m in selected})

    if missing:
        raise ValueError(f"Missing manifests for datasets: {missing}")

    return selected