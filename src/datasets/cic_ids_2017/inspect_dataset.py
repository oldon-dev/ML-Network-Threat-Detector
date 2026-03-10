from pathlib import Path

import pandas as pd


DATA_PATH = Path("data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    print(f"Loading dataset from: {DATA_PATH}\n")

    df = pd.read_csv(DATA_PATH)

    print("Shape:")
    print(df.shape)
    print()

    print("Column names:")
    for i, col in enumerate(df.columns):
        print(f"[{i}] {col}")
    print()

    print("First 5 rows:")
    print(df.head())
    print()

    print("Data types:")
    print(df.dtypes)
    print()

    print("Missing values per column:")
    print(df.isna().sum())
    print()

    if "Label" in df.columns:
        print("Label value counts:")
        print(df["Label"].astype(str).value_counts())
        print()
    else:
        print("No 'Label' column found.\n")

    print("Checking for infinity values in numeric columns...")
    numeric_df = df.select_dtypes(include=["number"])
    inf_counts = (~numeric_df.apply(lambda s: pd.Series(s).replace([float("inf"), float("-inf")], pd.NA).notna()).sum())
    print("Done.")
    print()

    print("Sample numeric summary:")
    print(numeric_df.describe().T.head(20))


if __name__ == "__main__":
    main()