import gzip
import pickle
import pandas as pd

import _pickle as cPickle
from ember_model import NeedForSpeedModel

def load_gzip_pickle(filename):
    fp = gzip.open(filename,'rb')
    obj = cPickle.load(fp)
    fp.close()
    return obj

print("Loading test features...")

with open("/root/ByteMe/models/ember_test_data.pkl", "rb") as f:
    test_attributes = pickle.load(f)

print("Loading saved classifer...")
clf = load_gzip_pickle("/root/ByteMe/models/ember_model.pkl")

test_data = pd.DataFrame(test_attributes)
# shuffle
test_data = test_data.sample(frac=1).reset_index(drop=True)
# pick first 1000
test_data = test_data[:10000]
test_data = test_data[(test_data["label"]==1) | (test_data["label"]==0)]
#print(test_data)
print(test_data.shape)

print("Predicting...")
y_pred = clf.predict(test_data)

from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from sklearn.metrics import confusion_matrix

print("calculating metrics...")
test_label = test_data["label"].values
acc = accuracy_score(test_label, y_pred)
print("Acc:", acc)

tn, fp, fn, tp = confusion_matrix(test_label, y_pred).ravel()

# Fall out or false positive rate
FPR = fp/(fp+tn)
# False negative rate
FNR = fn/(tp+fn)
# # False discovery rate
# FDR = FP/(TP+FP)
print("FPR:", FPR)
print("FNR:", FNR)
