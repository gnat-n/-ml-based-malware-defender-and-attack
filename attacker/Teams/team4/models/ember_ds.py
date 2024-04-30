import pandas as pd
import os, gzip
import pickle

from tqdm import tqdm

from attribute_extractor import JSONAttributeExtractor


ds_dir = "/root/datasets/ember/"
output_pkl_path = "ember_train_data_1.pkl"
prefix = "train_"
train_attributes = []

def process_file(file_path):
    
    with gzip.open(file_path, 'rb') as file_gzip:
        for line in tqdm(file_gzip.readlines()):
            at_ext = JSONAttributeExtractor(line)
            atts = at_ext.extract()
            train_attributes.append(atts)



if __name__ == "__main__":
    # Iterate through files in the directory
    for root, dirs, files in os.walk(ds_dir):
        for file in files:
            if file.endswith(".jsonl.gz") and file.startswith(prefix):
                print(f"Processing {file}")
                file_path = os.path.join(root, file)
                process_file(file_path)
                print("====")
    # save to pickle
    with open(output_pkl_path, 'wb') as f:
        pickle.dump(train_attributes, f)
    print("Done")
    # read the csv file
    # data = pd.read_csv(output_csv_path)
    # # print number of nan values
    # replace null values with zeros
    # print(data.isnull().sum())
