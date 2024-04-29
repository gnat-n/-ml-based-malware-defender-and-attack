import os
import pandas as pd
from main import extract_pe_features

# Load PE Header and PE Section DataFrames
df1 = pd.read_csv('/root/ByteMe/datasets/1/PE_Header.csv')
df2 = pd.read_csv('/root/ByteMe/datasets/1/PE_Section.csv')

# Merge DataFrames
df = pd.merge(df1, df2, on=['SHA256', 'Type'], how='inner')

# Directory containing the .exe files
exe_directory = '/root/ali/files/'

# Iterate over all .exe files in the directory
for filename in os.listdir(exe_directory):
    if filename.endswith('.exe'):
        bin_path = os.path.join(exe_directory, filename)
        # extract file name (hash)
        file_hash = filename[:-4]
        features = extract_pe_features(bin_path)
        original_features = df[df['SHA256'] == file_hash].drop(
            columns=['SHA256', 'Type'])

        print(f"Validating for {file_hash}")
        print("=== Validation started ===")

        # Validate keys only
        for key in features.keys():
            if key not in original_features.keys():
                print(f'Key {key} not found in original features')

        print("=== Validation 1/3 complete ===")

        for key in original_features.keys():
            if key not in features.keys():
                print(f'Key {key} not found in extracted features')

        print("=== Validation 2/3 complete ===")

        # Validate values
        for key in features.keys():
            # check if key is in original features
            if key not in original_features.keys():
                print(f'Key {key} not found in original features')
                print("===")
                continue
            if len(original_features[key].values) != 1:
                print(f'Key {key} has more than one value')
                print("===")
                continue
            if len(original_features[key].values) == 0:
                print(f'Key {key} has no value')
                print("===")
                continue
            if features[key] != original_features[key].values[0]:
                print(f'Value for key {key} does not match')
                print(f'Original: {original_features[key].values[0]}')
                print(f'Extracted: {features[key]}')
                print("===")

        for key in original_features.keys():
            if key in ("SHA256", "Type", "Type_x", "Type_y"):
                continue

            if key not in features.keys():
                print(f'Key {key} not found in extracted features')
                print("===")
                continue

            if len(original_features[key].values) != 1:
                print(f'Key {key} has more than one value')
                print("===")
                continue
            
            if len(original_features[key].values) == 0:
                print(f'Key {key} has no value')
                print("===")
                continue

            if features[key] != original_features[key].values[0]:
                print(f'Value for key {key} does not match')
                print(f'Original: {original_features[key].values[0]}')
                print(f'Extracted: {features[key]}')
                print("===")

        print("=== Validation 3/3 complete ===")
        print('-' * 75)
