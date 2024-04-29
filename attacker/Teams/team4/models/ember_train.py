import pandas as pd
import gzip

import _pickle as cPickle

import pickle

from ember_model import NeedForSpeedModel, RandomForestClassifier


def save_gzip_pickle(filename, obj):
    fp = gzip.open(filename, 'wb')
    cPickle.dump(obj, fp)
    fp.close()

# read pkl file
with open("train_2.pkl", 'rb') as f:
    train_attributes = pickle.load(f)
    print(f"Loaded {len(train_attributes)} training samples")
train_data = pd.DataFrame(train_attributes)
print("Converted to DataFrame")

clf = NeedForSpeedModel(classifier=RandomForestClassifier(n_jobs=-1, verbose=1))
clf.fit(train_data)
# save model
save_gzip_pickle("model_2.pkl", clf)
q