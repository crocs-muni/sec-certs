from typing import Dict, List, Set, Optional, Union

import pandas as pd
import numpy as np
import tqdm
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.base import BaseEstimator
from sklearn.neighbors import NearestNeighbors

import sec_certs.helpers as helpers
from sec_certs.dataset.cve import CVE

# Hyperparameters below
N_TOKENS = 20
CUTOFF_DISTANCE = 0.9


class VulnClassifier(BaseEstimator):
    def __init__(self, keywords: Set[str]):
        self.keywords: Set[str] = keywords

        self.vulnerabilities: Optional[List[CVE]] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.feature_matrix: Optional[np.array] = None

    def _discard_vulns_with_few_tokens(self):
        self.vulnerabilities = [x for x in self.vulnerabilities if len(x.tokenized.split(' ')) > 5]

    def _preprocess_vulnerabilities(self):
        for vuln in self.vulnerabilities:
            vuln.tokenize(self.keywords)
        self._discard_vulns_with_few_tokens()

    def fit(self, X: List[CVE], y=None):
        self.vulnerabilities = X
        self._preprocess_vulnerabilities()
        self.vectorizer = TfidfVectorizer(stop_words='english', vocabulary=self.keywords,
                                          token_pattern=r'(?u)\b[a-zA-Z0-9_.]{2,}\b')
        self.feature_matrix = self.vectorizer.fit_transform([x.tokenized for x in self.vulnerabilities])
        self.feature_matrix = self.feature_matrix.todense()

    def predict(self, X: List[str]) -> List[List[CVE]]:
        return [self.predict_single_cert(x) for x in tqdm.tqdm(X, desc='Predicting')]

    def predict_single_cert(self, cert):
        description = helpers.tokenize(cert, self.keywords)
        feature_vector = self.vectorizer.transform([description]).todense().A1
        max_indicies = np.argpartition(feature_vector, -N_TOKENS)[-N_TOKENS:]
        subset_feature_matrix = self.feature_matrix[:, max_indicies]  # Select only some features

        # # TODO: Check if not making mistake here
        # scaler = StandardScaler()
        # feature_matrix = scaler.fit_transform(feature_matrix)
        # feature_vector = scaler.transform(feature_vector[max_indicies].reshape(1,-1))

        clf = NearestNeighbors()
        clf.fit(subset_feature_matrix)

        distances, indicies = clf.kneighbors(feature_vector[max_indicies].reshape(1, -1), return_distance=True)
        filtered = list(filter(lambda x: x[0] < CUTOFF_DISTANCE, list(zip(distances.flatten(), indicies.flatten()))))
        return [self.vulnerabilities[x[1]] for x in filtered]

    def prepare_df_from_description(self, description):
        description = helpers.tokenize(description, self.keywords)
        matrix = self.vectorizer.transform([description]).todense()
        feature_index = matrix[0, :].nonzero()[1]
        tfidf_scores = list(
            zip([self.vectorizer.get_feature_names()[i] for i in feature_index], [matrix[0, x] for x in feature_index]))
        tfidf_scores = dict(sorted(tfidf_scores, key=lambda item: item[1], reverse=True))
        tfidf_scores = pd.DataFrame.from_dict(tfidf_scores, orient='index', columns=['TF-IDF'])
        tfidf_scores.index.name = 'token'
        return tfidf_scores