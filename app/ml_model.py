import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
import json

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.dbscan = DBSCAN(
            eps=0.5,
            min_samples=5
        )

    def extract_features(self, query):
        """Extract features from SQL query"""
        features = {
            'query_length': len(query),
            'keyword_count': sum(1 for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']
                               if keyword in query.upper()),
            'special_char_count': sum(1 for char in query if char in "!@#$%^&*()"),
            'table_count': query.upper().count('FROM') + query.upper().count('JOIN'),
            'condition_count': query.upper().count('WHERE') + query.upper().count('AND') + query.upper().count('OR')
        }
        return features

    def features_to_vector(self, features):
        """Convert feature dictionary to vector"""
        return np.array([
            features['query_length'],
            features['keyword_count'],
            features['special_char_count'],
            features['table_count'],
            features['condition_count']
        ]).reshape(1, -1)

    def train(self, queries):
        """Train the anomaly detection models"""
        feature_vectors = []
        for query in queries:
            features = self.extract_features(query)
            feature_vectors.append(self.features_to_vector(features).flatten())
        
        X = np.array(feature_vectors)
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        self.isolation_forest.fit(X_scaled)
        self.dbscan.fit(X_scaled)

    def is_anomaly(self, query):
        """Detect if a query is anomalous"""
        features = self.extract_features(query)
        feature_vector = self.features_to_vector(features)
        X_scaled = self.scaler.transform(feature_vector)
        
        # Combine results from both models
        is_anomaly_if = self.isolation_forest.predict(X_scaled)[0] == -1
        is_anomaly_dbscan = self.dbscan.fit_predict(X_scaled)[0] == -1
        
        return is_anomaly_if or is_anomaly_dbscan, features 