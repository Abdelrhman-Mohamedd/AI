"""
Machine learning models for vulnerability detection and urgency prediction.
"""

import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression, LinearRegression, Ridge, Lasso
from sklearn.preprocessing import PolynomialFeatures, StandardScaler
from sklearn.pipeline import Pipeline
from typing import Literal, Optional, Tuple
import os


class VulnerabilityClassifier:
    """
    Binary classifier for detecting vulnerable code using Logistic Regression.
    """
    
    def __init__(self, C: float = 1.0, max_iter: int = 2000, random_state: int = 42, class_weight: str = 'balanced'):
        """
        Initialize the vulnerability classifier.
        
        Args:
            C: Inverse of regularization strength (smaller = stronger regularization)
            max_iter: Maximum iterations for optimization
            random_state: Random seed for reproducibility
            class_weight: Weight balancing strategy ('balanced' handles imbalanced data)
        """
        self.model = LogisticRegression(
            C=C,
            max_iter=max_iter,
            random_state=random_state,
            solver='lbfgs',
            class_weight=class_weight  # Handle imbalanced data
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def train(self, X: np.ndarray, y: np.ndarray) -> 'VulnerabilityClassifier':
        """
        Train the classifier on labeled data.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Binary labels (0=safe, 1=vulnerable)
            
        Returns:
            Self for method chaining
        """
        # Standardize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train logistic regression
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict vulnerability labels.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Binary predictions (0=safe, 1=vulnerable)
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before prediction")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict vulnerability probabilities.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Probability matrix (n_samples, 2) - [P(safe), P(vulnerable)]
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before prediction")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def get_vulnerability_score(self, X: np.ndarray) -> np.ndarray:
        """
        Get vulnerability probability score (0-1).
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Vulnerability probabilities for each sample
        """
        proba = self.predict_proba(X)
        return proba[:, 1]  # Probability of being vulnerable
    
    def save(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: File path to save the model (.pkl)
        """
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        joblib.dump({'model': self.model, 'scaler': self.scaler, 'is_fitted': self.is_fitted}, path)
    
    @classmethod
    def load(cls, path: str) -> 'VulnerabilityClassifier':
        """
        Load a trained model from disk.
        
        Args:
            path: File path to load the model from
            
        Returns:
            Loaded VulnerabilityClassifier instance
        """
        data = joblib.load(path)
        instance = cls()
        instance.model = data['model']
        instance.scaler = data.get('scaler', StandardScaler())  # Handle old models
        instance.is_fitted = data.get('is_fitted', True)  # Handle old models
        return instance


class UrgencyPredictor:
    """
    Regressor for predicting patch urgency scores (0-100) using Linear/Ridge/Lasso Regression.
    """
    
    def __init__(
        self, 
        model_type: Literal['linear', 'ridge', 'lasso'] = 'linear',
        alpha: float = 1.0,
        use_polynomial: bool = False,
        poly_degree: int = 2,
        random_state: int = 42
    ):
        """
        Initialize the urgency predictor.
        
        Args:
            model_type: Type of regression model ('linear', 'ridge', 'lasso')
            alpha: Regularization strength for Ridge/Lasso
            use_polynomial: Whether to use polynomial features
            poly_degree: Degree of polynomial features (if use_polynomial=True)
            random_state: Random seed for reproducibility
        """
        self.model_type = model_type
        self.alpha = alpha
        self.use_polynomial = use_polynomial
        self.poly_degree = poly_degree
        self.random_state = random_state
        
        # Select regression model
        if model_type == 'ridge':
            regressor = Ridge(alpha=alpha, random_state=random_state)
        elif model_type == 'lasso':
            regressor = Lasso(alpha=alpha, random_state=random_state, max_iter=2000)
        else:  # linear
            regressor = LinearRegression()
        
        # Build pipeline with optional polynomial features
        if use_polynomial:
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('poly', PolynomialFeatures(degree=poly_degree, include_bias=False)),
                ('regressor', regressor)
            ])
        else:
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('regressor', regressor)
            ])
        
        self.is_fitted = False
    
    def train(self, X: np.ndarray, y: np.ndarray) -> 'UrgencyPredictor':
        """
        Train the regressor on labeled data.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Urgency scores (0-100)
            
        Returns:
            Self for method chaining
        """
        # Ensure urgency scores are in valid range
        y_clipped = np.clip(y, 0, 100)
        
        # Train regression model
        self.model.fit(X, y_clipped)
        self.is_fitted = True
        
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict urgency scores.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Urgency score predictions (0-100)
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before prediction")
        
        predictions = self.model.predict(X)
        
        # Clip predictions to valid range
        return np.clip(predictions, 0, 100)
    
    def save(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: File path to save the model (.pkl)
        """
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        joblib.dump({
            'model': self.model,
            'model_type': self.model_type,
            'alpha': self.alpha,
            'use_polynomial': self.use_polynomial,
            'poly_degree': self.poly_degree,
            'is_fitted': self.is_fitted
        }, path)
    
    @classmethod
    def load(cls, path: str) -> 'UrgencyPredictor':
        """
        Load a trained model from disk.
        
        Args:
            path: File path to load the model from
            
        Returns:
            Loaded UrgencyPredictor instance
        """
        data = joblib.load(path)
        instance = cls(
            model_type=data.get('model_type', 'linear'),
            alpha=data.get('alpha', 1.0),
            use_polynomial=data.get('use_polynomial', False),
            poly_degree=data.get('poly_degree', 2)
        )
        instance.model = data['model']
        instance.is_fitted = data.get('is_fitted', True)
        return instance


def evaluate_classifier(
    classifier: VulnerabilityClassifier, 
    X_test: np.ndarray, 
    y_test: np.ndarray
) -> dict:
    """
    Evaluate classifier performance.
    
    Args:
        classifier: Trained VulnerabilityClassifier
        X_test: Test feature matrix
        y_test: True labels
        
    Returns:
        Dictionary with evaluation metrics
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
    
    y_pred = classifier.predict(X_test)
    y_proba = classifier.predict_proba(X_test)[:, 1]
    
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall': recall_score(y_test, y_pred, zero_division=0),
        'f1_score': f1_score(y_test, y_pred, zero_division=0),
        'roc_auc': roc_auc_score(y_test, y_proba) if len(np.unique(y_test)) > 1 else 0.0
    }
    
    return metrics


def evaluate_regressor(
    predictor: UrgencyPredictor, 
    X_test: np.ndarray, 
    y_test: np.ndarray
) -> dict:
    """
    Evaluate regressor performance.
    
    Args:
        predictor: Trained UrgencyPredictor
        X_test: Test feature matrix
        y_test: True urgency scores
        
    Returns:
        Dictionary with evaluation metrics
    """
    from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
    
    y_pred = predictor.predict(X_test)
    
    metrics = {
        'mse': mean_squared_error(y_test, y_pred),
        'rmse': np.sqrt(mean_squared_error(y_test, y_pred)),
        'mae': mean_absolute_error(y_test, y_pred),
        'r2_score': r2_score(y_test, y_pred)
    }
    
    return metrics
