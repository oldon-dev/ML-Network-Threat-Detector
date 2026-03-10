from pathlib import Path
import pandas as pd


DATA_DIR = Path("data/raw/CTU-13")


def main():
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Directory not found: {DATA_DIR}")

    files = sorted(DATA_DIR.rglob("*.binetflow"))
    if not files:
        raise FileNotFoundError(f"No .binetflow files found in: {DATA_DIR}")

    print("Found .binetflow files:\n")
    for i, f in enumerate(files):
        print(f"[{i}] {f}")

    target = files[0]
    print(f"\nInspecting: {target}\n")

    df = pd.read_csv(target)

    print("Shape:")
    print(df.shape)
    print()

    print("Columns:")
    for i, col in enumerate(df.columns):
        print(f"[{i}] {col}")
    print()

    print("First 5 rows:")
    print(df.head())
    print()

    print("Dtypes:")
    print(df.dtypes)
    print()

    label_candidates = [c for c in df.columns if "label" in c.lower()]
    print("Possible label columns:")
    print(label_candidates)
    print()

    for col in label_candidates:
        print(f"Value counts for {col}:")
        print(df[col].astype(str).value_counts().head(20))
        print()


if __name__ == "__main__":
    main()