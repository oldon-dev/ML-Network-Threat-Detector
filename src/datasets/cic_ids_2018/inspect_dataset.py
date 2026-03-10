from pathlib import Path
import pandas as pd

RAW_DIR = Path("data/raw/cic-ids-2018")


def main() -> None:
    files = sorted(RAW_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {RAW_DIR}")

    print(f"Found {len(files)} parquet files in {RAW_DIR}\n")

    for path in files:
        print("=" * 100)
        print(f"FILE: {path.name}")

        df = pd.read_parquet(path)

        print(f"Shape: {df.shape}")
        print("\nColumns:")
        for i, col in enumerate(df.columns):
            print(f"[{i}] {col}")

        print("\nDtypes:")
        print(df.dtypes)

        label_candidates = [
            c for c in df.columns
            if str(c).strip().lower() in {"label", "attack", "category"}
        ]

        if label_candidates:
            for label_col in label_candidates:
                print(f"\nLabel column candidate: {label_col}")
                print(df[label_col].astype(str).value_counts(dropna=False).head(30))
        else:
            print("\nNo obvious label column found.")

        print("\nHead:")
        print(df.head(3))
        print()

    print("Inspection complete.")


if __name__ == "__main__":
    main()