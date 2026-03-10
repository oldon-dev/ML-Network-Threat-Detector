from pathlib import Path
import pandas as pd

RAW_DIR = Path("data/raw/ton_iot")


def main() -> None:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")

    for path in files:
        print("=" * 100)
        print(f"FILE: {path.name}")
        df = pd.read_csv(path, low_memory=False)

        print(f"Shape: {df.shape}")
        print("\nColumns:")
        for i, col in enumerate(df.columns):
            print(f"[{i}] {col}")

        print("\nDtypes:")
        print(df.dtypes)

        label_candidates = [
            c for c in df.columns
            if c.strip().lower() in {"label", "type", "attack", "attack_type", "category"}
        ]
        if label_candidates:
            label_col = label_candidates[0]
            print(f"\nLabel column candidate: {label_col}")
            print(df[label_col].astype(str).value_counts(dropna=False).head(30))
        else:
            print("\nNo obvious label column found.")

        print("\nHead:")
        print(df.head(3))
        print()


if __name__ == "__main__":
    main()