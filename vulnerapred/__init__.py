"""
Vulnerability Patch Urgency Predictor

A machine learning system for detecting vulnerable code and predicting patch urgency.
Now with AST-based analysis for enhanced accuracy!
"""

__version__ = "2.0.0"
__author__ = "AI Course Project"

from .models import VulnerabilityClassifier, UrgencyPredictor
from .features import CodeFeatureExtractor

try:
    from .ast_analyzer import ASTVulnerabilityAnalyzer, analyze_code_ast
    __all__ = [
        'VulnerabilityClassifier', 
        'UrgencyPredictor', 
        'CodeFeatureExtractor',
        'ASTVulnerabilityAnalyzer',
        'analyze_code_ast'
    ]
except ImportError:
    # AST analyzer not available
    __all__ = ['VulnerabilityClassifier', 'UrgencyPredictor', 'CodeFeatureExtractor']
