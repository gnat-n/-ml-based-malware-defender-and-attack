from attribute_extractor import AttributeExtractor
# Assuming features_list is the list of features extracted from the samples

# Get the keys from your attribute extractor
pe_file_path = "D:\Yash-docs\Assignments-TAMU\ML\ML_model\ML-for-Cyber-Competition\defense\datasets\mw2\0001"
extractor_keys = set()
with open(pe_file_path, "rb") as file:  # replace pe_file_path with the path to a PE file
    pe_bytes = file.read()
    extractor = AttributeExtractor(pe_bytes)
    extractor.extract_and_preprocess()
    extractor_keys.update(extractor.header_attributes.keys())
    for section in extractor.section_attributes.values():
        extractor_keys.update(section.keys())

# Get the keys from the samples
sample_keys = set()
for features in features_list:
    for key in features.keys():
        if isinstance(features[key], dict):
            sample_keys.update(features[key].keys())
        else:
            sample_keys.add(key)

# Get the features that the attribute extractor is not considering
missing_features = sample_keys - extractor_keys

print("Features not considered in attribute extractor:", missing_features)