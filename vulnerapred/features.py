"""
Feature extraction module for code analysis.

Extracts numerical features from code snippets for ML models.
"""

import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import List, Dict, Any
import pandas as pd

try:
    from .ast_analyzer import analyze_code_ast
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False


class CodeFeatureExtractor:
    """Extract features from code snippets for vulnerability detection and urgency prediction."""
    
    def __init__(self, max_features: int = 100, use_tfidf: bool = True, use_ast: bool = True):
        """
        Initialize the feature extractor.
        
        Args:
            max_features: Maximum number of TF-IDF features to extract
            use_tfidf: Whether to use TF-IDF features (True) or simple statistical features only
            use_ast: Whether to use AST-based analysis for enhanced detection
        """
        self.max_features = max_features
        self.use_tfidf = use_tfidf
        self.use_ast = use_ast and AST_AVAILABLE
        self.vectorizer = None
        
        if self.use_tfidf:
            # TF-IDF vectorizer for code tokens
            self.vectorizer = TfidfVectorizer(
                max_features=max_features,
                token_pattern=r'\b\w+\b',  # Simple word tokenization
                lowercase=True,
                ngram_range=(1, 2)  # Use unigrams and bigrams
            )
    
    def extract_statistical_features(self, code: str) -> Dict[str, float]:
        """
        Extract statistical features from code snippet.
        
        Args:
            code: Code snippet as string
            
        Returns:
            Dictionary of feature names and values
        """
        features = {}
        
        # AST-based features (if enabled)
        if self.use_ast:
            ast_vulnerabilities = analyze_code_ast(code)
            features['ast_vuln_count'] = len(ast_vulnerabilities)
            features['ast_high_severity'] = sum(1 for v in ast_vulnerabilities if v.get('severity') == 'high')
            features['ast_medium_severity'] = sum(1 for v in ast_vulnerabilities if v.get('severity') == 'medium')
            features['ast_low_severity'] = sum(1 for v in ast_vulnerabilities if v.get('severity') == 'low')
            
            # Count specific vulnerability types found by AST
            vuln_types = [v.get('type', '') for v in ast_vulnerabilities]
            features['ast_code_injection'] = vuln_types.count('code_injection')
            features['ast_command_injection'] = vuln_types.count('command_injection')
            features['ast_sql_injection'] = vuln_types.count('sql_injection')
            features['ast_insecure_deserialization'] = vuln_types.count('insecure_deserialization')
            features['ast_xxe'] = vuln_types.count('xxe')
            features['ast_weak_cryptography'] = vuln_types.count('weak_cryptography')
        
        # Basic length features
        features['code_length'] = len(code)
        features['line_count'] = code.count('\n') + 1
        features['avg_line_length'] = len(code) / max(1, features['line_count'])
        
        # Character-based features
        features['whitespace_ratio'] = sum(c.isspace() for c in code) / max(1, len(code))
        features['digit_count'] = sum(c.isdigit() for c in code)
        features['special_char_count'] = sum(not c.isalnum() and not c.isspace() for c in code)
        
        # Complexity indicators
        features['parentheses_count'] = code.count('(') + code.count(')')
        features['bracket_count'] = code.count('[') + code.count(']')
        features['brace_count'] = code.count('{') + code.count('}')
        features['semicolon_count'] = code.count(';')
        features['comma_count'] = code.count(',')
        
        # Dangerous function indicators (vulnerability signals)
        dangerous_patterns = [
            r'(?<![a-zA-Z_\"])eval\s*\(', r'(?<![a-zA-Z_\"])exec\s*\(', r'(?<![a-zA-Z_])system\s*\(', r'(?<![a-zA-Z_])popen\s*\(',
            r'\bshell\s*=\s*True', r'(?<![a-zA-Z_])input\s*\(', r'(?<![a-zA-Z_])raw_input\s*\(',
            r'__import__', r'(?<![a-zA-Z_])compile\s*\(', r'(?<![a-zA-Z_])globals\s*\(', r'(?<![a-zA-Z_])locals\s*\(',
            r'pickle\.loads?\s*\(', r'subprocess\.', r'os\.system\s*\(',
            r'hashlib\.md5\s*\(', r'hashlib\.sha1\s*\(',
            r'pickle\.dumps?\s*\(', r'yaml\.load\s*\(',
            r'requests\.get\s*\(', r'requests\.post\s*\(', r'urllib\.urlopen\s*\('
        ]
        
        features['dangerous_functions'] = sum(
            len(re.findall(pattern, code, re.IGNORECASE)) 
            for pattern in dangerous_patterns
        )
        
        # SQL injection indicators
        # Remove comments to avoid false positives
        code_no_comments = re.sub(r'#.*', '', code)  # Remove line comments
        code_no_comments = re.sub(r'"""[\s\S]*?"""', '', code_no_comments)  # Remove docstrings
        code_no_comments = re.sub(r"'''[\s\S]*?'''", '', code_no_comments)  # Remove docstrings
        
        sql_patterns = [r'\bSELECT\b', r'\bINSERT\b', r'\bUPDATE\b', r'\bDELETE\b', 
                       r'\bFROM\b', r'\bWHERE\b', r'\bJOIN\b', r'\bDROP\b', r'\bUNION\b']
        features['sql_keywords'] = sum(
            len(re.findall(pattern, code_no_comments, re.IGNORECASE)) 
            for pattern in sql_patterns
        )
        
        # SQL injection specific patterns
        # Check for f-strings with SQL keywords (more flexible pattern)
        features['has_sql_fstring'] = 1 if (re.search(r'f["\'][^"\']*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"\']*\{', code, re.IGNORECASE | re.DOTALL) is not None) else 0
        features['has_sql_string_concat'] = 1 if (re.search(r'(\+.*["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b|\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*["\'].*\+)', code, re.IGNORECASE) is not None) else 0
        features['has_sql_format_method'] = 1 if (re.search(r'\.format\(.*\).*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b', code, re.IGNORECASE) is not None) else 0
        
        # Check for execute/query calls with variables (not parameterized)
        features['has_execute_with_concat'] = 1 if (re.search(r'\.(execute|query)\([^)]*\+', code) is not None) else 0
        features['has_execute_with_fstring'] = 1 if (re.search(r'\.(execute|query)\(\s*f["\']', code) is not None) else 0
        features['has_execute_with_variable'] = 1 if (re.search(r'\.(execute|query)\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', code) is not None and re.search(r'\.(execute|query)\([^)]*[\?,][^)]*\)', code) is None) else 0
        
        # Check for parameterized queries (safe pattern)
        features['has_parameterized_query'] = 1 if (re.search(r'\.(execute|query)\([^)]*\?', code) is not None or re.search(r'\.(execute|query)\([^)]*%s', code) is not None or re.search(r'\.(execute|query)\([^)]*,\s*\(', code) is not None) else 0
        
        # SQL keywords combined with variable interpolation
        features['sql_and_variable_interpolation'] = 1 if (features['sql_keywords'] > 0 and (re.search(r'\{[^}]+\}', code) is not None or re.search(r'%s', code) is not None or re.search(r"'\s*\+", code) is not None)) else 0
        
        # Check for query variable assignment with f-string or concat
        features['query_var_with_sql_injection'] = 1 if (re.search(r'query\s*=\s*f["\'][^"\']*\b(SELECT|INSERT|UPDATE|DELETE)\b', code, re.IGNORECASE) is not None or re.search(r'query\s*=.*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\+', code, re.IGNORECASE) is not None) else 0
        
        # XSS/injection indicators
        features['script_tag_count'] = len(re.findall(r'<script', code, re.IGNORECASE))
        features['html_tag_count'] = len(re.findall(r'<\w+', code))
        
        # String concatenation (often used in injections)
        features['string_operations'] = code.count('+') + code.count('+=') + code.count('.format') + len(re.findall(r'f["\']', code))
        features['string_concat_count'] = code.count('+') + code.count('+=')
        features['format_string_count'] = code.count('%s') + code.count('{}') + code.count('.format')
        
        # File operations
        file_patterns = [r'\bopen\s*\(', r'\.read\s*\(', r'\.write\s*\(', 
                        r'\.readlines\s*\(', r'os\.path', r'Path\s*\(']
        features['file_operations'] = sum(
            len(re.findall(pattern, code, re.IGNORECASE)) 
            for pattern in file_patterns
        )
        
        # Network operations
        network_patterns = [r'requests\.', r'urllib\.', r'socket\.', r'http\.client']
        features['network_operations'] = sum(
            len(re.findall(pattern, code, re.IGNORECASE)) 
            for pattern in network_patterns
        )
        
        # Control flow complexity
        features['if_count'] = len(re.findall(r'\bif\b', code))
        features['for_count'] = len(re.findall(r'\bfor\b', code))
        features['while_count'] = len(re.findall(r'\bwhile\b', code))
        features['try_count'] = len(re.findall(r'\btry\b', code))
        features['except_count'] = len(re.findall(r'\bexcept\b', code))
        
        # Function/method calls
        features['function_call_count'] = len(re.findall(r'\w+\s*\(', code))
        
        # Assignment operations
        features['assignment_count'] = code.count('=') - code.count('==') - code.count('!=')
        
        return features
    
    def fit_transform(self, code_snippets: List[str]) -> np.ndarray:
        """
        Fit the vectorizer and transform code snippets to feature vectors.
        
        Args:
            code_snippets: List of code snippet strings
            
        Returns:
            Feature matrix (n_samples, n_features)
        """
        # Extract statistical features for all snippets
        stat_features = []
        for code in code_snippets:
            features = self.extract_statistical_features(code)
            stat_features.append(features)
        
        stat_df = pd.DataFrame(stat_features)
        
        if self.use_tfidf and self.vectorizer is not None:
            # Fit and transform TF-IDF features
            tfidf_features = self.vectorizer.fit_transform(code_snippets).toarray()
            
            # Combine statistical and TF-IDF features
            combined_features = np.hstack([stat_df.values, tfidf_features])
            return combined_features
        else:
            return stat_df.values
    
    def transform(self, code_snippets: List[str]) -> np.ndarray:
        """
        Transform code snippets to feature vectors using fitted vectorizer.
        
        Args:
            code_snippets: List of code snippet strings
            
        Returns:
            Feature matrix (n_samples, n_features)
        """
        # Extract statistical features
        stat_features = []
        for code in code_snippets:
            features = self.extract_statistical_features(code)
            stat_features.append(features)
        
        stat_df = pd.DataFrame(stat_features)
        
        if self.use_tfidf and self.vectorizer is not None:
            # Transform using fitted vectorizer
            tfidf_features = self.vectorizer.transform(code_snippets).toarray()
            
            # Combine features
            combined_features = np.hstack([stat_df.values, tfidf_features])
            return combined_features
        else:
            return stat_df.values
    
    def get_feature_names(self) -> List[str]:
        """
        Get names of all extracted features.
        
        Returns:
            List of feature names
        """
        # Statistical feature names (from a sample extraction)
        sample_features = self.extract_statistical_features("sample code")
        stat_names = list(sample_features.keys())
        
        if self.use_tfidf and self.vectorizer is not None:
            # Add TF-IDF feature names
            tfidf_names = [f'tfidf_{name}' for name in self.vectorizer.get_feature_names_out()]
            return stat_names + tfidf_names
        else:
            return stat_names


def extract_features_from_file(file_path: str, extractor: CodeFeatureExtractor) -> np.ndarray:
    """
    Extract features from a code file.
    
    Args:
        file_path: Path to code file
        extractor: Fitted CodeFeatureExtractor instance
        
    Returns:
        Feature vector for the file
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    
    return extractor.transform([code])
