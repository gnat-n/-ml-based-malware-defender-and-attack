# Didatic Example on how to classify PE files as malware vs. goodware

import sys              # Read argv. You can read from file too.
import pefile           # lib to parse PE file. Change lib to parse ELF
from sklearn import svm # Some ML classifier, you can change it

# Receive [goodware, malware, and unknown file] as argument
gw_train = sys.argv[1]
mw_train = sys.argv[2]
unknown  = sys.argv[3]

# Parse goodware file
# I'm considering only one to be didactic
# In real world, you should consider multiple files in a loop
# Study task: Consider multiple files
pe1=pefile.PE(gw_train)
# Number of imports (libraries) as feature
# Single feature to be didcatice
# in real world, use a vector of features
# Study task: Consider multiple features!
pe_gw_imps = len(pe1.DIRECTORY_ENTRY_IMPORT)

# Do the same for the malware file
pe2=pefile.PE(mw_train)
pe_mw_imps = len(pe2.DIRECTORY_ENTRY_IMPORT)

# Create vectors to be classified
# Feature in X. Labels in Y
X = [[pe_gw_imps],[pe_mw_imps]]
# 0=goodware, 1=malware
Y = [0,1]

# Instantiate a classifier and train it with the vectors
clf = svm.SVC()
clf.fit(X, Y)

# Now parse the unknown file
pe3=pefile.PE(unknown)
pe_ukn_imps = len(pe3.DIRECTORY_ENTRY_IMPORT)

# Ask classifier if unknown is malware or goodware
res = int(clf.predict([[pe_ukn_imps]]))

# Instead of printing 0 or 1, print name
label_map = ["goodware","malware"]
print(label_map[res])
