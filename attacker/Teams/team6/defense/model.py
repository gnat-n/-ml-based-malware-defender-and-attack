from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_selection import mutual_info_classif, SelectKBest



class MalwareDetectionModel():

    def __init__(self,
                    vocabulary,
                    classifier=RandomForestClassifier(),
                    numerical_extractor = StandardScaler(),
                    selector = SelectKBest(score_func=mutual_info_classif, k='all'),
                    textual_extractor=1,
                    pca = PCA(n_components=0.95)
                ) -> None:
        
        self.classifier = classifier
        self.textual_extractor = CountVectorizer(vocabulary=vocabulary, binary=True) if textual_extractor==1 else TfidfVectorizer(vocabulary=vocabulary,ngram_range=(1,2))
        self.numerical_extractor = numerical_extractor
        self.pca = pca
        self.selector = selector

    
    # train a textual extractor
    def _train_textual_extractor(self, textual_atts):
        self.textual_extractor.fit(textual_atts)

    
    # transform textual extractor
    def _transform_textual_extractor(self, textual_atts):
        return self.textual_extractor.transform(textual_atts)
    

    # train numerical extractor
    def _train_numerical_extractor(self, numerical_atts):
        self.numerical_extractor.fit(numerical_atts)
    

    def _transform_numerical_extractor(self, numerical_atts):
        return self.numerical_extractor.transform(numerical_atts)
    

    def combine_raw_features(self, ifs1, ifs2):
        # convert ifs2 to sparse matrix
        ifs2_sparse = csr_matrix(ifs2)
        # stack horizontally
        return hstack([ifs1, ifs2_sparse])



    def train_and_transform_feature_selection(self, features_combined, labels):
        # apply on dense data
        features_dense = features_combined.toarray()

        # PCA for dimensionality reduction
        reduced_features = self.pca.fit_transform(features_dense)

        # apply information gain (select k best)
        selected_features = self.selector.fit_transform(reduced_features, labels)

        return selected_features
    

    def test_and_transform_feature_selection(self, features_combined):
        # apply on dense data
        features_dense = features_combined.toarray()

        # apply pca
        reduced_features = self.pca.transform(features_dense)

        # apply IG
        selected_features = self.selector.transform(reduced_features)
        
        return selected_features
    
    
    # training complete model
    def fit(self, textual_atts, numerical_atts, labels):
        # train textual and numerical extractors
        self._train_textual_extractor(textual_atts)
        self._train_numerical_extractor(numerical_atts)

        # transform textual and numerical extractors
        text_feature_vector = self._transform_textual_extractor(textual_atts)
        numeric_feature_vector = self._transform_numerical_extractor(numerical_atts)

        # get combined feature set
        combined_features = self.combine_raw_features(text_feature_vector, numeric_feature_vector)

        # apply PCA and information gain
        transformed_features = self.train_and_transform_feature_selection(combined_features, labels)

        # # concatenate raw features with transformed features
        # combined_features_dense = combined_features.toarray()
        # all_features = np.hstack((combined_features_dense, transformed_features))

        # train classifier
        self.classifier.fit(transformed_features, labels)
    

    def extract_features_test_data(self, test_text_atts, test_num_atts):
        # create feature vectors
        text_feat_vec = self._transform_textual_extractor(test_text_atts)
        num_feat_vec = self._transform_numerical_extractor(test_num_atts)

        # combine text and num features
        combined = self.combine_raw_features(text_feat_vec, num_feat_vec)

        # apply dimensionality and feature selection
        transformed_feats = self.test_and_transform_feature_selection(combined)

        return transformed_feats

    # predict class
    def predict(self, test_text_atts, test_num_atts):
        transformed_feats = self.extract_features_test_data(test_text_atts, test_num_atts)

        return self.classifier.predict(transformed_feats)
    
    
    # predict probability of being a class
    def predict_proba(self, test_text_atts, test_num_atts):
        transformed_feats = self.extract_features_test_data(test_text_atts, test_num_atts)

        return self.classifier.predict_proba(transformed_feats)
    

    # predict with probability and threshold
    def predict_threshold(self, test_text_atts, test_num_atts, threshold=0.75):
        probs = self.predict_proba(test_text_atts, test_num_atts)[:, 1]  # Probabilities for the positive class
        return (probs >= threshold).astype(int)