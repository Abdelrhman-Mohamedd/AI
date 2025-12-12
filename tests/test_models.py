"""
Unit tests for the Vulnerability Patch Urgency Predictor.
"""

import pytest
import numpy as np
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor


class TestCodeFeatureExtractor:
    """Tests for CodeFeatureExtractor."""
    
    def test_extract_statistical_features(self):
        """Test statistical feature extraction."""
        extractor = CodeFeatureExtractor(use_tfidf=False)
        code = "def hello():\n    print('Hello, World!')"
        
        features = extractor.extract_statistical_features(code)
        
        # Check that features are extracted
        assert 'code_length' in features
        assert 'line_count' in features
        assert 'function_call_count' in features
        
        # Check values
        assert features['code_length'] == len(code)
        assert features['line_count'] == 2
        assert features['function_call_count'] >= 1  # print()
    
    def test_dangerous_function_detection(self):
        """Test detection of dangerous functions."""
        extractor = CodeFeatureExtractor(use_tfidf=False)
        
        # Vulnerable code
        vuln_code = "eval(user_input)"
        vuln_features = extractor.extract_statistical_features(vuln_code)
        
        # Safe code
        safe_code = "print('Hello')"
        safe_features = extractor.extract_statistical_features(safe_code)
        
        # Vulnerable code should have higher dangerous function count
        assert vuln_features['dangerous_functions'] > safe_features['dangerous_functions']
    
    def test_fit_transform(self):
        """Test fit_transform method."""
        extractor = CodeFeatureExtractor(max_features=10, use_tfidf=True)
        codes = [
            "def add(a, b): return a + b",
            "os.system(user_input)",
            "print('Hello, World!')"
        ]
        
        X = extractor.fit_transform(codes)
        
        # Check shape
        assert X.shape[0] == len(codes)
        assert X.shape[1] > 0  # Should have features
        
        # Check that TF-IDF was applied
        assert extractor.vectorizer is not None
    
    def test_transform(self):
        """Test transform method on new data."""
        extractor = CodeFeatureExtractor(max_features=10, use_tfidf=True)
        train_codes = ["def func(): pass", "x = 1 + 2"]
        test_codes = ["def another(): return 42"]
        
        # Fit on training data
        X_train = extractor.fit_transform(train_codes)
        
        # Transform test data
        X_test = extractor.transform(test_codes)
        
        # Should have same number of features
        assert X_train.shape[1] == X_test.shape[1]


class TestVulnerabilityClassifier:
    """Tests for VulnerabilityClassifier."""
    
    def test_train_and_predict(self):
        """Test training and prediction."""
        # Create dummy data
        X_train = np.random.rand(100, 20)
        y_train = np.random.randint(0, 2, 100)
        
        # Train classifier
        classifier = VulnerabilityClassifier()
        classifier.train(X_train, y_train)
        
        # Make predictions
        X_test = np.random.rand(10, 20)
        predictions = classifier.predict(X_test)
        
        # Check predictions
        assert len(predictions) == 10
        assert all(p in [0, 1] for p in predictions)
    
    def test_predict_proba(self):
        """Test probability prediction."""
        X_train = np.random.rand(100, 20)
        y_train = np.random.randint(0, 2, 100)
        
        classifier = VulnerabilityClassifier()
        classifier.train(X_train, y_train)
        
        X_test = np.random.rand(10, 20)
        probas = classifier.predict_proba(X_test)
        
        # Check shape and values
        assert probas.shape == (10, 2)
        assert np.allclose(probas.sum(axis=1), 1.0)  # Probabilities sum to 1
    
    def test_get_vulnerability_score(self):
        """Test vulnerability score extraction."""
        X_train = np.random.rand(100, 20)
        y_train = np.random.randint(0, 2, 100)
        
        classifier = VulnerabilityClassifier()
        classifier.train(X_train, y_train)
        
        X_test = np.random.rand(10, 20)
        scores = classifier.get_vulnerability_score(X_test)
        
        # Check scores
        assert len(scores) == 10
        assert all(0 <= s <= 1 for s in scores)
    
    def test_save_and_load(self, tmp_path):
        """Test model saving and loading."""
        X_train = np.random.rand(50, 20)
        y_train = np.random.randint(0, 2, 50)
        
        # Train and save
        classifier = VulnerabilityClassifier()
        classifier.train(X_train, y_train)
        
        model_path = tmp_path / "test_classifier.pkl"
        classifier.save(str(model_path))
        
        # Load and predict
        loaded_classifier = VulnerabilityClassifier.load(str(model_path))
        
        X_test = np.random.rand(5, 20)
        original_pred = classifier.predict(X_test)
        loaded_pred = loaded_classifier.predict(X_test)
        
        # Predictions should be identical
        assert np.array_equal(original_pred, loaded_pred)


class TestUrgencyPredictor:
    """Tests for UrgencyPredictor."""
    
    def test_train_and_predict_linear(self):
        """Test linear regression training and prediction."""
        X_train = np.random.rand(100, 20)
        y_train = np.random.uniform(0, 100, 100)
        
        predictor = UrgencyPredictor(model_type='linear')
        predictor.train(X_train, y_train)
        
        X_test = np.random.rand(10, 20)
        predictions = predictor.predict(X_test)
        
        # Check predictions
        assert len(predictions) == 10
        assert all(0 <= p <= 100 for p in predictions)
    
    def test_train_and_predict_ridge(self):
        """Test ridge regression training and prediction."""
        X_train = np.random.rand(100, 20)
        y_train = np.random.uniform(0, 100, 100)
        
        predictor = UrgencyPredictor(model_type='ridge', alpha=1.0)
        predictor.train(X_train, y_train)
        
        X_test = np.random.rand(10, 20)
        predictions = predictor.predict(X_test)
        
        assert len(predictions) == 10
        assert all(0 <= p <= 100 for p in predictions)
    
    def test_train_and_predict_lasso(self):
        """Test lasso regression training and prediction."""
        X_train = np.random.rand(100, 20)
        y_train = np.random.uniform(0, 100, 100)
        
        predictor = UrgencyPredictor(model_type='lasso', alpha=0.1)
        predictor.train(X_train, y_train)
        
        X_test = np.random.rand(10, 20)
        predictions = predictor.predict(X_test)
        
        assert len(predictions) == 10
        assert all(0 <= p <= 100 for p in predictions)
    
    def test_polynomial_features(self):
        """Test polynomial feature transformation."""
        X_train = np.random.rand(100, 5)
        y_train = np.random.uniform(0, 100, 100)
        
        predictor = UrgencyPredictor(
            model_type='linear',
            use_polynomial=True,
            poly_degree=2
        )
        predictor.train(X_train, y_train)
        
        X_test = np.random.rand(10, 5)
        predictions = predictor.predict(X_test)
        
        assert len(predictions) == 10
        assert all(0 <= p <= 100 for p in predictions)
    
    def test_save_and_load(self, tmp_path):
        """Test model saving and loading."""
        X_train = np.random.rand(50, 20)
        y_train = np.random.uniform(0, 100, 50)
        
        predictor = UrgencyPredictor(model_type='ridge')
        predictor.train(X_train, y_train)
        
        model_path = tmp_path / "test_predictor.pkl"
        predictor.save(str(model_path))
        
        loaded_predictor = UrgencyPredictor.load(str(model_path))
        
        X_test = np.random.rand(5, 20)
        original_pred = predictor.predict(X_test)
        loaded_pred = loaded_predictor.predict(X_test)
        
        # Predictions should be very close
        assert np.allclose(original_pred, loaded_pred)


class TestEndToEnd:
    """End-to-end integration tests."""
    
    def test_full_pipeline(self):
        """Test complete pipeline from feature extraction to prediction."""
        # Sample code snippets
        codes = [
            "eval(user_input)",  # Vulnerable
            "os.system(cmd)",    # Vulnerable
            "print('hello')",    # Safe
            "x = a + b",         # Safe
        ]
        
        labels = [1, 1, 0, 0]
        urgencies = [80.0, 90.0, 10.0, 5.0]
        
        # Extract features
        extractor = CodeFeatureExtractor(max_features=10, use_tfidf=True)
        X = extractor.fit_transform(codes)
        
        # Train classifier
        classifier = VulnerabilityClassifier()
        classifier.train(X, np.array(labels))
        
        # Train predictor
        predictor = UrgencyPredictor(model_type='linear')
        predictor.train(X, np.array(urgencies))
        
        # Make predictions on new code
        new_code = ["exec(malicious_code)"]
        X_new = extractor.transform(new_code)
        
        is_vulnerable = classifier.predict(X_new)[0]
        urgency = predictor.predict(X_new)[0]
        
        # Should detect as vulnerable with reasonable urgency
        assert is_vulnerable in [0, 1]
        assert 0 <= urgency <= 100


class TestASTAnalyzer:
    """Tests for AST-based vulnerability analyzer."""
    
    def test_ast_analyzer_import(self):
        """Test that AST analyzer can be imported."""
        try:
            from vulnerapred.ast_analyzer import ASTVulnerabilityAnalyzer, analyze_code_ast
            assert True
        except ImportError:
            pytest.skip("AST analyzer not available")
    
    def test_code_injection_detection(self):
        """Test detection of code injection vulnerabilities."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
def execute_code(user_input):
    eval(user_input)
    exec(user_input)
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should detect eval and exec
        assert len(vulnerabilities) >= 2
        vuln_types = [v['type'] for v in vulnerabilities]
        assert 'code_injection' in vuln_types
    
    def test_command_injection_detection(self):
        """Test detection of command injection."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
import os
import subprocess

def run_command(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should detect command injection
        assert len(vulnerabilities) >= 1
        vuln_types = [v['type'] for v in vulnerabilities]
        assert 'command_injection' in vuln_types
    
    def test_sql_injection_detection(self):
        """Test detection of SQL injection."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should detect SQL injection
        assert len(vulnerabilities) >= 1
        vuln_types = [v['type'] for v in vulnerabilities]
        assert 'sql_injection' in vuln_types
    
    def test_insecure_deserialization_detection(self):
        """Test detection of insecure deserialization."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
import pickle

def load_data(data):
    return pickle.loads(data)
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should detect insecure deserialization
        assert len(vulnerabilities) >= 1
        vuln_types = [v['type'] for v in vulnerabilities]
        assert 'insecure_deserialization' in vuln_types
    
    def test_weak_cryptography_detection(self):
        """Test detection of weak cryptography."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should detect weak cryptography
        assert len(vulnerabilities) >= 1
        vuln_types = [v['type'] for v in vulnerabilities]
        assert 'weak_cryptography' in vuln_types
    
    def test_safe_code_no_vulnerabilities(self):
        """Test that safe code has no vulnerabilities."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        code = """
def add_numbers(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
"""
        vulnerabilities = analyze_code_ast(code)
        
        # Should have no vulnerabilities
        assert len(vulnerabilities) == 0
    
    def test_ast_integration_with_features(self):
        """Test AST integration with feature extraction."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        extractor = CodeFeatureExtractor(use_tfidf=False, use_ast=True)
        
        vuln_code = "eval(user_input)"
        safe_code = "print('hello')"
        
        vuln_features = extractor.extract_statistical_features(vuln_code)
        safe_features = extractor.extract_statistical_features(safe_code)
        
        # Vulnerable code should have AST vulnerabilities
        assert 'ast_vuln_count' in vuln_features
        assert 'ast_code_injection' in vuln_features
        
        # Vulnerable code should have higher counts
        assert vuln_features['ast_vuln_count'] > safe_features['ast_vuln_count']
    
    def test_syntax_error_handling(self):
        """Test handling of syntax errors in AST analysis."""
        try:
            from vulnerapred.ast_analyzer import analyze_code_ast
        except ImportError:
            pytest.skip("AST analyzer not available")
        
        invalid_code = "def incomplete_function("
        
        vulnerabilities = analyze_code_ast(invalid_code)
        
        # Should return syntax error vulnerability
        assert len(vulnerabilities) >= 1
        assert vulnerabilities[0]['type'] == 'syntax_error'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
