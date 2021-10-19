from typing import Dict, List, Set, Optional, Union, Any

import pandas as pd
import numpy as np
import tqdm
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.base import BaseEstimator
from sklearn.neighbors import NearestNeighbors
import seaborn as sns
import sec_certs.helpers as helpers
from sec_certs.sample.cve import CVE


class VulnClassifier(BaseEstimator):
    """
    On developing custom estimators: https://scikit-learn.org/stable/developers/develop.html
    """
    vulnerabilities_: List[str]
    labels_: List[str]
    vectorizer_: TfidfVectorizer
    feature_matrix_: Any

    def __init__(self, keywords: Optional[Set[str]] = None, cutoff_distance: float = 0.9, n_tokens: int = 20):
        self.keywords = keywords
        self.cutoff_distance = cutoff_distance
        self.n_tokens = n_tokens

    def fit(self, X: List[str], y: List[str] = None):
        self.vulnerabilities_ = X
        self.labels_ = y
        self.vectorizer_ = TfidfVectorizer(stop_words='english', vocabulary=self.keywords,
                                           token_pattern=r'(?u)\b[a-zA-Z0-9_.]{2,}\b')
        self.feature_matrix_ = self.vectorizer_.fit_transform(X)
        self.feature_matrix_ = self.feature_matrix_.todense()
        return self

    def predict(self, X: List[str], return_distances=False):
        if not return_distances:
            return [self.predict_single_cert(x) for x in tqdm.tqdm(X, desc='Predicting')]
        else:
            return list(map(list, zip(*[self.predict_single_cert(x, return_distances=True) for x in tqdm.tqdm(X, desc='Predicting')])))

    def predict_single_cert(self, cert: str, return_distances: bool = False, n_neighbors: int = 5):
        feature_vector = self.vectorizer_.transform([cert]).todense().A1
        max_indicies = np.argpartition(feature_vector, -self.n_tokens)[-self.n_tokens:]
        subset_feature_matrix = self.feature_matrix_[:, max_indicies]

        # # TODO: Check if not making mistake here
        # scaler = StandardScaler()
        # feature_matrix = scaler.fit_transform(feature_matrix)
        # feature_vector = scaler.transform(feature_vector[max_indicies].reshape(1,-1))

        clf = NearestNeighbors(algorithm='brute', metric='cosine', n_neighbors=n_neighbors)
        clf.fit(subset_feature_matrix)

        distances, indicies = clf.kneighbors(feature_vector[max_indicies].reshape(1, -1), return_distance=True)
        filtered = list(filter(lambda x: x[0] < self.cutoff_distance, list(zip(distances.flatten(), indicies.flatten()))))

        result = np.array([self.labels_[x[1]][0] for x in filtered]) if filtered else np.array(['None'])
        if not return_distances:
            return result
        else:
            return result, [x[0] for x in filtered]

    def plot_histogram_of_distances(self, x, outpath='histogram_of_distances.png'):
        result, distances = self.predict_single_cert(x, return_distances=True, n_neighbors=len(self.labels_))
        hist_plot = sns.histplot(data=distances, x='Cert distance to CVE', y='Distance frequency', bins=50)
        fig = hist_plot.get_figre()
        fig.savefig(outpath, dpli=300)

    def prepare_df_from_description(self, description: str):
        matrix = self.vectorizer_.transform([description]).todense()
        feature_index = matrix[0, :].nonzero()[1]
        tfidf_scores = list(
            zip([self.vectorizer_.get_feature_names()[i] for i in feature_index], [matrix[0, x] for x in feature_index]))
        tfidf_scores = dict(sorted(tfidf_scores, key=lambda item: item[1], reverse=True))
        tfidf_scores = pd.DataFrame.from_dict(tfidf_scores, orient='index', columns=['TF-IDF'])
        tfidf_scores.index.name = 'token'
        return tfidf_scores
