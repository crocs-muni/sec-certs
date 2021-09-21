from typing import Dict, List, Set, Optional, Union

import pandas as pd
import numpy as np
import tqdm
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.base import BaseEstimator
from sklearn.neighbors import NearestNeighbors

import sec_certs.helpers as helpers
from sec_certs.dataset.cve import CVE


class VulnClassifier(BaseEstimator):
    """
    On developing custom estimators: https://scikit-learn.org/stable/developers/develop.html
    """
    def __init__(self, keywords: Set[str], cutoff_distance: float = 0.9, n_tokens: int = 20):
        self.keywords: Set[str] = keywords
        self.cutoff_distance = cutoff_distance
        self.n_tokens = n_tokens

    def _discard_vulns_with_few_tokens(self):
        self.vulnerabilities_ = list(filter(lambda x: len(x.tokenized.split(' ')) > 5, self.vulnerabilities_))

    def _preprocess_vulnerabilities(self):
        for vuln in self.vulnerabilities_:
            vuln.tokenize(self.keywords)
        self._discard_vulns_with_few_tokens()

    def fit(self, X: List[CVE], y=None):
        self.vulnerabilities_ = X
        self._preprocess_vulnerabilities()
        self.vectorizer_ = TfidfVectorizer(stop_words='english', vocabulary=self.keywords,
                                           token_pattern=r'(?u)\b[a-zA-Z0-9_.]{2,}\b')
        self.feature_matrix_ = self.vectorizer_.fit_transform([x.tokenized for x in self.vulnerabilities_])
        self.feature_matrix_ = self.feature_matrix_.todense()
        return self

    def predict(self, X: List[str], return_distances=False):
        if not return_distances:
            return [self.predict_single_cert(x) for x in tqdm.tqdm(X, desc='Predicting')]
        else:
            return list(map(list, zip(*[self.predict_single_cert(x, return_distances=True) for x in tqdm.tqdm(X, desc='Predicting')])))

    def predict_single_cert(self, cert, return_distances: bool = False):
        description = helpers.tokenize(cert, self.keywords)
        feature_vector = self.vectorizer_.transform([description]).todense().A1

        # Select only some features
        max_indicies = np.argpartition(feature_vector, -self.n_tokens)[-self.n_tokens:]
        subset_feature_matrix = self.feature_matrix_[:, max_indicies]

        # # TODO: Check if not making mistake here
        # scaler = StandardScaler()
        # feature_matrix = scaler.fit_transform(feature_matrix)
        # feature_vector = scaler.transform(feature_vector[max_indicies].reshape(1,-1))

        clf = NearestNeighbors()
        clf.fit(subset_feature_matrix)

        distances, indicies = clf.kneighbors(feature_vector[max_indicies].reshape(1, -1), return_distance=True)
        filtered = list(filter(lambda x: x[0] < self.cutoff_distance, list(zip(distances.flatten(), indicies.flatten()))))

        if not return_distances:
            return [self.vulnerabilities_[x[1]] for x in filtered]
        else:
            return [self.vulnerabilities_[x[1]] for x in filtered], [x[0] for x in filtered]

    def prepare_df_from_description(self, description):
        description = helpers.tokenize(description, self.keywords)
        matrix = self.vectorizer_.transform([description]).todense()
        feature_index = matrix[0, :].nonzero()[1]
        tfidf_scores = list(
            zip([self.vectorizer_.get_feature_names()[i] for i in feature_index], [matrix[0, x] for x in feature_index]))
        tfidf_scores = dict(sorted(tfidf_scores, key=lambda item: item[1], reverse=True))
        tfidf_scores = pd.DataFrame.from_dict(tfidf_scores, orient='index', columns=['TF-IDF'])
        tfidf_scores.index.name = 'token'
        return tfidf_scores
