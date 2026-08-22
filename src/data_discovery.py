import pandas as pd

def explore_dataset(csv_filepath):
    print(f"--- Loading Dataset: {csv_filepath} ---")
    
    # The CIC datasets are huge, so we'll load just the first 100,000 rows for discovery
    try:
        df = pd.read_csv(csv_filepath, nrows=100000)
    except FileNotFoundError:
        print("Error: CSV file not found. Check your file path.")
        return

    print(f"\nDataset Shape: {df.shape[0]} rows, {df.shape[1]} columns")
    
    print("\n--- Feature Columns ---")
    # Print all columns to identify our temporal features (e.g., 'Flow Duration', 'Fwd IAT Mean')
    for col in df.columns:
        print(f"- {col}")
        
    print("\n--- Attack Labels Found ---")
    # The label column in CIC datasets is usually named ' Label' (sometimes with a leading space)
    label_col = [col for col in df.columns if 'Label' in col]
    
    if label_col:
        labels = df[label_col[0]].value_counts()
        print(labels)
    else:
        print("Could not find a 'Label' column.")

if __name__ == "__main__":
    # Update this path once you download the CSV
    target_csv = "../data/raw/cicddos2019_sample.csv"
    explore_dataset(target_csv)