import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import os
import random

"""
New train test splitting with the provided test datasets
- Train data: all of the previous training data we used + the previous test data
- Test data: the provided dataset from the prof
"""
def create_train_set(benign_train, mal_train):
    benign_paths = benign_train['datapoints']
    b_labels = benign_train['labels']
    mal_paths = mal_train['datapoints']
    m_labels = mal_train['labels']

    combined_datapoints = benign_paths + mal_paths
    combined_labels = b_labels + m_labels

    combined = list(zip(combined_datapoints, combined_labels))

    random.shuffle(combined)
    datapoints, labels = zip(*combined)

    return datapoints, labels

def create_test_sets(curr_dir):
    paths = [os.path.join(curr_dir, item) for item in os.listdir(curr_dir)]
    dir_name = curr_dir[-3:]
    labels = [1] * len(paths) if 'mw' in dir_name else [0] * len(paths)

    return {"datapoints": paths, "labels": labels}, dir_name



# def split_dataset(directory_path, is_malware=1):

#     X = [os.path.join(directory_path, item) for item in os.listdir(directory_path)]
#     y = [is_malware] * len(X)


#     X_train, X_test, y_train, y_test = train_test_split(
#         X,y , random_state=104,test_size=0.3, shuffle=True
#     )

#     train_combined = list(zip(X_train, y_train))
#     test_combined = list(zip(X_test, y_test))
    
#     return train_combined, test_combined



# def combine_and_shuffle(dataset1, dataset2):
#     combined = dataset1 + dataset2
#     random.shuffle(combined)

#     datapoints, labels = zip(*combined)

#     return datapoints, labels


if __name__=='__main__':
    with open('train_and_test_data/final_benign.json') as f:
        benign_train_set = json.load(f)
        
    with open('train_and_test_data/final_malignant.json') as f:
        mal_train_set = json.load(f)

    train_dataponts, train_labels = create_train_set(benign_train_set, mal_train_set)
    with open('train_data_balanced.json', 'w') as f:
        json.dump({'datapoints': train_dataponts, 'labels': train_labels}, f)

    # test_dir = '../../TestDataset'
    # for dir in os.listdir(test_dir):
    #     if '.DS' in dir:
    #         continue
    #     curr_dir = os.path.join(test_dir, dir)
    #     curr_test_dict, dir_name = create_test_sets(curr_dir)
    #     with open(dir_name + '.json', 'w') as f:
    #         json.dump(curr_test_dict, f)

    # benign_train, benign_test = split_dataset(benign_dir, 0)
    # mal_train, mal_test = split_dataset(malware_dir)

    # train_datapoints, train_labels = combine_and_shuffle(benign_train, mal_train)
    # test_datapoints, test_labels = combine_and_shuffle(benign_test, mal_test)

    # train_data = {
    #     'datapoints': train_datapoints,
    #     'labels': train_labels
    # }

    # test_data = {
    #     'datapoints': test_datapoints,
    #     'labels': test_labels
    # }

    # with open('train_data.json', 'w') as f:
    #         json.dump(train_data, f)

    # with open('test_data.json', 'w') as f:
    #         json.dump(test_data, f)
