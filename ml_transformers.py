import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

from feature_extractor import extract_url_features


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []

        for url in X:
            rows.append(extract_url_features(str(url)))

        return pd.DataFrame(rows)