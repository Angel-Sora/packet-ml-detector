# Packet ML Detector - ML-based Network Anomaly Detection System
# Copyright (C) 2026 Angel-Sora
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import pandas as pd
import os

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'packet_len', 'ttl', 'tcp_win', 
            'payload_size', 'ip_frag', 'ip_len'
        ]
        
    def prepare_features(self, packets):
        df = pd.DataFrame(packets)
        X = df[self.feature_names].fillna(0).values
        return X
        
    def train(self, packets, contamination=0.01):
        if len(packets) < 100:
            raise ValueError("Нужно минимум 100 пакетов для обучения!")
            
        X = self.prepare_features(packets)
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        return self.model
        
    def predict(self, packet):
        if self.model is None:
            return None
            
        X = self.prepare_features([packet])
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)[0]
    
    def predict_batch(self, packets):
        X = self.prepare_features(packets)
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
        
    def save(self, path="models/anomaly_detector.pkl"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, path)
        
    def load(self, path="models/anomaly_detector.pkl"):
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data.get('feature_names', self.feature_names)
