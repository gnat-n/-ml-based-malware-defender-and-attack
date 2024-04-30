from model import MalwareDetectionModel
# from attribute_extractor import AttributeExtractor
from attribute_extractor2 import AttributeExtractor
import argparse
import json
import numpy as np
from joblib import dump, load
from sklearn.metrics import accuracy_score, f1_score, precision_recall_curve, recall_score, precision_score
from sklearn.model_selection import StratifiedKFold
from xgboost import XGBClassifier
from sklearn.preprocessing import MinMaxScaler
import os


def get_preprocessed_attributes(data_json_path, need_vocabulary=False):
    ifs2_atts = []
    ifs1_atts = []
    labels = [] 

    # vocabulary lists
    vocabulary = []

    with open(data_json_path) as f:
        data = json.load(f)
    num_iterations = len(data['datapoints'])

    i = 1
    for filepath, label in zip(data['datapoints'], data['labels']):
        try:
            with open(filepath, "rb") as file:
                pe_bytes = file.read()
        except:
            print(f"WARNING: file not found {filepath}. Skipping...")
            continue
        
        extractor = AttributeExtractor(pe_bytes)
        if not extractor.pe:
            continue

        extractor.extract_header_fields()
        extractor.extract_sections_fields()
        extractor.extract_dlls_and_api_calls()

        # new attributes
        extractor.extract_entropy() 
        extractor.extract_exported_functions() # incorporated into header attributes dictionary

        # create vocabulary
        if need_vocabulary:
            vocabulary.extend(extractor.dll_attributes)
            vocabulary.extend(extractor.api_attributes) 
            vocabulary.extend(extractor.exported_functions)

        dll = extractor.dll_attributes
        api = extractor.api_attributes
        dll_exports = extractor.exported_functions

        # list of lists are inputted with sublists containing DLL and API names
        # need to concatenate names within each sublist to form strings
        ifs1_atts.append(' '.join(dll + api + dll_exports)) # include exports in textual representation

        header_values = list(extractor.header_attributes.values())
        section_values = [value for section in extractor.section_attributes.values() for value in section.values()]

        ifs2_atts.append(header_values + section_values)

        labels.append(label) 

        if i % 20 == 0 or i == num_iterations:
            print(f"Extracted attributes of {i}/{num_iterations} PEs")

        i+=1

    
    # convert to numpy array for numerical extractors (BoW, TF-IDF, etc.)
    ifs2_atts = np.array(ifs2_atts)

    # make vocabulary unique
    vocabulary = list(set(vocabulary))

    if need_vocabulary:
        return ifs1_atts, ifs2_atts, labels, vocabulary
    else:
        return ifs1_atts, ifs2_atts, labels

# from concurrent.futures import ThreadPoolExecutor, as_completed
# import os

# parallelize code to speed extraction
# def process_file(filepath, label):
#     try:
#         with open(filepath, "rb") as file:
#             pe_bytes = file.read()
        
#         extractor = AttributeExtractor(pe_bytes)
#         if not extractor.pe:
#             return None

#         extractor.extract_header_fields()
#         extractor.extract_sections_fields()
#         extractor.extract_dlls_and_api_calls()

#         dll = extractor.dll_attributes
#         api = extractor.api_attributes
#         ifs1_att = ' '.join(dll + api)

#         header_values = list(extractor.header_attributes.values())
#         section_values = [value for section in extractor.section_attributes.values() for value in section.values()]
#         ifs2_att = header_values + section_values

#         return ifs1_att, ifs2_att, label
#     except Exception as e:
#         print(f"Error processing {os.path.basename(filepath)}: {e}")
#         return None

# def get_preprocessed_attributes(data_json_path):
    # ifs1_atts = []
    # ifs2_atts = []
    # labels = []

    # with open(data_json_path) as f:
    #     data = json.load(f)

    # create a ThreadPoolExecutor to parallelize operations
    # with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    #     futures = [executor.submit(process_file, filepath, label) for filepath, label in zip(data['datapoints'], data['labels'])]

    #     for i, future in enumerate(as_completed(futures)):
    #         # print("here")
    #         result = future.result()
    #         if result:
    #             ifs1_att, ifs2_att, label = result
    #             ifs1_atts.append(ifs1_att)
    #             ifs2_atts.append(ifs2_att)
    #             labels.append(label)
            
    #         if (i + 1) % 20 == 0 or (i + 1) == len(data['datapoints']):
    #             print(f"Extracted attributes of {i + 1}/{len(data['datapoints'])} PEs")

    # return ifs1_atts, np.array(ifs2_atts), labels



def evaluate_model(y_true, y_pred, model_description):
    print(f"Performance of the model with {model_description}")
    print("-------------------------------------------------------")
    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("Recall/TPR:", recall_score(y_true, y_pred))
    print("Precision:", precision_score(y_true, y_pred))
    print("F1 score:", f1_score(y_true, y_pred))



if __name__=='__main__':
    # Parsing command line arguments
    parser = argparse.ArgumentParser(
        description="Train or test the model"
    )
    parser.add_argument(
        '--train',
        action=argparse.BooleanOptionalAction,
        help='Use this flag if you want to train the model.'
    )
    parser.add_argument(
        '--test',
        action=argparse.BooleanOptionalAction,
        help='Use this flag if you want to test the model.'
    )

    args = parser.parse_args()
    train_model = args.train
    test_model = args.test

    if train_model:
        print("Mode: Train Model")
        # Extract attributes
        print("Extracting attributes...")
        train_path = './train_and_test_data_updated/train_data.json'
        ifs1_atts, ifs2_atts, labels, vocabulary = get_preprocessed_attributes(train_path, need_vocabulary=True)

        # with open('train_attributes_balanced.json') as f:
        #     atts = json.load(f)

        # ifs1_atts = atts['ifs1']
        # ifs2_atts = atts['ifs2']
        # labels = atts['labels']

        # save ifs1, ifs2, labels in case of training/testing error
        with open('train_atts_new_feats.json', 'w') as f:
            json.dump({'ifs1': ifs1_atts, 'ifs2': ifs2_atts.tolist(), 'labels': labels}, f)

        # converting vocabulary for tfidf
        vocabulary_dict = {term: i for i, term in enumerate(vocabulary)}

        # train the model with 5-fold cross-validation
        print("Creating feature vectors and training the model...")

        model = MalwareDetectionModel(
            vocabulary=vocabulary_dict,
            classifier=XGBClassifier(),
            numerical_extractor=MinMaxScaler(),
            textual_extractor=0 # using tf-idf
        )

        # print(ifs2_atts)
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        accuracies = []
        f1_scores = []
        thresholds_list = []

        for train_index, test_index in skf.split(ifs2_atts, labels):
            # setting up the current fold's data
            train_ifs1, test_ifs1 = [ifs1_atts[i] for i in train_index], [ifs1_atts[i] for i in test_index]
            train_ifs2 = [ifs2_atts[i] for i in train_index]
            test_ifs2 = [ifs2_atts[i] for i in test_index]
            train_labels, test_labels = [labels[i] for i in train_index], [labels[i] for i in test_index]

            # fit the model on the training data
            model.fit(train_ifs1, train_ifs2, train_labels)

            # find best threshold
            probs = model.predict_proba(test_ifs1, test_ifs2)[:, 1] # only getting probs of being malware to help with threshold adjustment
            precisions, recalls, thresholds = precision_recall_curve(test_labels, probs)
            f1_scores_threshold = 2 * (precisions * recalls) / (precisions + recalls)
            best_threshold = thresholds[np.argmax(f1_scores_threshold)]
            thresholds_list.append(best_threshold)

            # predict on validation set with new threshold
            y_pred = model.predict_threshold(test_ifs1, test_ifs2, threshold=best_threshold)

            # evaluate and store each fold's performance
            accuracy = accuracy_score(test_labels, y_pred)
            print(f"Current accuracy: {accuracy}")
            accuracies.append(accuracy)
            f1_scores.append(f1_score(test_labels, y_pred))

        # Print the average of the performance metrics across all folds
        print(f'Average Accuracy: {np.mean(accuracies)}')
        print(f'Average F1 Score: {np.mean(f1_scores)}')
        best_threshold = np.mean(thresholds_list)
        with open('best_threshold.json', 'w') as f:
            json.dump({'best_threshold': best_threshold})

        print(f'Best threshold: {best_threshold}')
            
        # model.fit(ifs1_atts, ifs2_atts, labels)
        print("Model is trained")
        # print(f'Average Accuracy: {np.mean(accuracies)}')

        # save the model
        dump(model, 'model_new_feats.joblib')
        print('Model is saved')


    if test_model:
        print("Mode: Test Model")

        model = load('model_balanced_data.joblib')

        with open('best_threshold.json') as f:
            best_threshold = json.load(f)['best_threshold']
        
        test_path = 'train_and_test_data_updated/test_data'
        for pe in os.listdir(test_path):
            dataset_name = pe[:3]
            data_json_path = os.path.join(test_path, pe)

            if '.DS' in data_json_path:
                continue

            print(f"Extracting attributes for {dataset_name}...")
            ifs1_atts, ifs2_atts, labels = get_preprocessed_attributes(data_json_path)

            # with open(dataset_name + "_test_atts" + ".json", 'w') as f:
            #     json.dump({'ifs1': ifs1_atts, 'ifs2': ifs2_atts.tolist(), 'labels': labels}, f)
            
            y_pred = model.predict_threshold(ifs1_atts, ifs2_atts, best_threshold)
            evaluate_model(labels, y_pred, dataset_name + ": standard predictions")
            print("-------------------------------------------------------")
            
        # # Extract attributes
        # print("Extracting attributes...")
        # test_path = '../train_and_test_data/test_data.json'
        # ifs1_atts, ifs2_atts, labels = get_preprocessed_attributes(test_path)

        # # save ifs1, ifs2, labels in case of testing error
        # with open('test_attributes_updated.json', 'w') as f:
        #     json.dump({'ifs1': ifs1_atts, 'ifs2': ifs2_atts.tolist(), 'labels': labels}, f)

        # # evaluate model
        # model = load('malware_detection_model.joblib')
        # y_pred = model.predict(ifs1_atts, ifs2_atts)
        # y_pred_threshold = model.predict_threshold(ifs1_atts, ifs2_atts)

        # evaluate_model(labels, y_pred, "standard predictions")
        # evaluate_model(labels, y_pred_threshold, "threshold predictions")



    if not train_model and not test_model:
        print("No training or testing done, please pass the proper argument.")