import pandas as pd

from main import extract_pe_features

df1 = pd.read_csv('/root/ByteMe/datasets/1/PE_Header.csv')
df2 = pd.read_csv('/root/ByteMe/datasets/1/PE_Section.csv')

df = pd.merge(df1, df2, on=['SHA256', 'Type'], how='inner')

bin_path = '/root/ali/files/a0afc068c4c03cbf7bcebb5d1207fd00079d4cf91dd226ab578a09ff11364998.exe'
# extract file name
file_hash= bin_path.split('/')[-1][:-4]
features = extract_pe_features(bin_path)
original_features = df[df['SHA256'] == file_hash].drop(columns=['SHA256', 'Type'])

print(original_features)

features_df = pd.DataFrame(features, index=[0])
# make the order of columns same
features_df = features_df[original_features.columns]

print(features_df)

