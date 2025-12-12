# Vulnerability Detection & Patch Urgency Predictor

A comprehensive machine learning system that detects security vulnerabilities in Python code and predicts patch urgency scores for risk prioritization. This project combines traditional ML models with Abstract Syntax Tree (AST) analysis and pattern detection for robust, context-aware vulnerability detection.

## Features

### Core Capabilities
- **Vulnerability Detection**: Binary classification (vulnerable vs. safe) using Logistic Regression, Random Forest, or XGBoost
- **Urgency Prediction**: Numeric urgency scores (0-100) using Linear/Ridge/Lasso Regression for patch prioritization
- **AST-Based Analysis**: Context-aware vulnerability detection using Abstract Syntax Trees
- **Pattern Detection**: Regex-based detection of known vulnerability signatures
- **Hybrid Detection**: Combines machine learning, AST analysis, and pattern matching for maximum accuracy
- **Feature Extraction**: TF-IDF, code complexity metrics, AST features, and 30+ statistical features
- **Risk Assessment**: Multi-dimensional risk factor analysis (complexity, dangerous functions, input handling, etc.)
- **GUI Application**: Modern Tkinter interface for interactive code analysis
- **CLI Tools**: Comprehensive command-line tools for training, evaluation, and prediction
- **Real-World Datasets**: Trained on synthetic data, CVE-like patterns, and real CVE examples

### Supported Vulnerability Types
- **SQL Injection** (CWE-89): String concatenation in queries, unparameterized statements
- **Command Injection** (CWE-78): Unsafe `os.system()`, `subprocess` with `shell=True`
- **Code Injection** (CWE-94): `eval()`, `exec()`, `compile()` with untrusted input
- **Deserialization** (CWE-502): `pickle.loads()`, `marshal.loads()`, unsafe YAML
- **XSS** (CWE-79): Unescaped HTML output, direct user input in templates
- **Path Traversal** (CWE-22): Unsanitized file paths, directory traversal
- **XXE** (CWE-611): Unsafe XML parsing without entity protection
- **Weak Cryptography**: MD5, SHA1, weak hashing algorithms
- **Hardcoded Credentials** (CWE-798): Hardcoded passwords, API keys, secrets

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- `scikit-learn` - Machine learning models
- `pandas` - Data manipulation
- `numpy` - Numerical computing
- `xgboost` - Gradient boosting (optional)
- `tkinter` - GUI framework (usually pre-installed with Python)

## Quick Start

### Option 1: Use Pre-trained Models (Recommended)

The project comes with pre-trained models in the `models/` directory. You can start analyzing code immediately:

```bash
# Analyze a code snippet
python predict.py --code "eval(user_input)" --snippet

# Analyze a Python file
python predict.py --file path/to/your_code.py

# Get JSON output
python predict.py --file code.py --json

# Verbose output with detailed analysis
python predict.py --file code.py --verbose
```

### Option 2: Train Your Own Models

#### 1. Dataset Information

The project uses a merged dataset combining:
- **training_dataset.csv**: 1000 synthetic vulnerable/safe code samples
- **cve_like_training.csv**: CVE-mapped vulnerability patterns with CWE codes
- **real_cve_dataset.csv**: Real-world CVE examples
- **merged_all_datasets.csv**: Combined dataset (recommended for training)

Generate additional synthetic data:
```bash
python data/generator.py
```

#### 2. Train Models

```bash
# Train with merged dataset (recommended)
python train.py --data data/merged_all_datasets.csv

# Train with specific dataset
python train.py --data data/training_dataset.csv

# Train with custom parameters
python train.py --classifier-model logistic --urgency-model ridge
```

This trains both models and saves them as:
- `models/vulnerability_classifier.pkl`
- `models/urgency_predictor.pkl`
- `models/feature_extractor.pkl`
- `models/classifier_metrics.json`
- `models/predictor_metrics.json`

#### 3. Evaluate Models

```bash
# Evaluate on test set
python evaluate.py

# Evaluate with specific model directory
python evaluate.py --model-dir models --data data/merged_all_datasets.csv
```

### Option 3: Use GUI Application

Launch the interactive GUI for real-time code analysis:

```bash
python gui_app.py
```

**GUI Features:**
- Paste or type code for instant analysis
- Visual vulnerability cards with severity indicators
- Risk factor dashboard
- Detailed recommendations
- Color-coded priority levels (Critical, High, Medium, Low)

## Project Structure

```
.
├── vulnerapred/                      # Core package
│   ├── __init__.py                   # Package initialization
│   ├── features.py                   # Feature extraction (TF-IDF, statistical, AST)
│   ├── models.py                     # ML model implementations (Classifier, Predictor)
│   ├── ast_analyzer.py               # AST-based vulnerability detection
│   └── utils.py                      # Helper functions and utilities
│
├── data/                             # Datasets
│   ├── generator.py                  # Synthetic vulnerable code generator
│   ├── generate_cve_like.py          # CVE-like pattern generator
│   ├── process_bigvul.py             # BigVul dataset processor
│   ├── training_dataset.csv          # Synthetic training data (1000 samples)
│   ├── cve_like_training.csv         # CVE-mapped vulnerability patterns
│   ├── real_cve_dataset.csv          # Real-world CVE examples
│   └── merged_all_datasets.csv       # Combined dataset (recommended)
│
├── models/                           # Trained models
│   ├── vulnerability_classifier.pkl   # Binary classifier model
│   ├── urgency_predictor.pkl         # Urgency score predictor
│   ├── feature_extractor.pkl         # TF-IDF vectorizer
│   ├── classifier_metrics.json       # Classifier performance metrics
│   └── predictor_metrics.json        # Predictor performance metrics
│
├── tests/                            # Unit tests
│   └── test_models.py                # Model and AST analyzer tests
│
├── train.py                          # Training pipeline CLI
├── predict.py                        # Prediction CLI (hybrid detection)
├── evaluate.py                       # Model evaluation CLI
├── gui_app.py                        # GUI application (Tkinter)
├── example.py                        # Full workflow demonstration
├── verify_learning.py                # ML learning verification
├── verify_learning_fixed.py          # Fixed verification script
├── requirements.txt                  # Python dependencies
├── README.md                         # This file
├── PERFORMANCE_IMPROVEMENTS.md       # Performance optimization notes
└── IMPROVEMENTS_APPLIED.md           # Feature enhancements log
```

## Usage Examples

### Command Line Interface

#### Prediction Examples

```bash
# Analyze code snippet
python predict.py --code "eval(user_input)" --snippet

# Analyze Python file
python predict.py --file vulnerable_code.py

# Get JSON output for integration
python predict.py --file code.py --json

# Verbose output with detailed analysis
python predict.py --file code.py --verbose

# Analyze specific functions
python predict.py --file code.py --function process_user_data
```

#### Training Examples

```bash
# Train with merged dataset (recommended)
python train.py --data data/merged_all_datasets.csv

# Train with specific models
python train.py --classifier-model random_forest --urgency-model ridge

# Train with custom output directory
python train.py --output-dir custom_models/
```

#### Evaluation Examples

```bash
# Evaluate trained models
python evaluate.py

# Evaluate with specific dataset
python evaluate.py --data data/real_cve_dataset.csv

# Evaluate with custom model directory
python evaluate.py --model-dir models/
```

### Python API

#### Using Pre-trained Models

```python
import pickle
from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.ast_analyzer import analyze_code_ast

# Load models
with open('models/vulnerability_classifier.pkl', 'rb') as f:
    classifier = pickle.load(f)
with open('models/urgency_predictor.pkl', 'rb') as f:
    predictor = pickle.load(f)
with open('models/feature_extractor.pkl', 'rb') as f:
    feature_extractor = pickle.load(f)

# Analyze code
code = "eval(user_input)"
features = feature_extractor.extract_features([code])
is_vulnerable = classifier.predict(features)[0]
urgency_score = predictor.predict(features)[0]

# AST analysis
ast_results = analyze_code_ast(code)
print(f"Vulnerable: {is_vulnerable}")
print(f"Urgency: {urgency_score:.1f}/100")
print(f"AST Findings: {ast_results}")
```

#### Training Custom Models

```python
from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor
from vulnerapred.features import CodeFeatureExtractor
import pandas as pd

# Load dataset
df = pd.read_csv('data/merged_all_datasets.csv')

# Extract features
extractor = CodeFeatureExtractor()
X = extractor.fit_transform(df['code'].tolist())
y = df['is_vulnerable'].values
urgency = df['urgency_score'].values

# Train models
classifier = VulnerabilityClassifier(model_type='logistic')
classifier.train(X, y)

predictor = UrgencyPredictor(model_type='linear')
predictor.train(X, urgency)

# Save models
classifier.save('models/my_classifier.pkl')
predictor.save('models/my_predictor.pkl')
extractor.save('models/my_extractor.pkl')
```

#### AST Analysis

```python
from vulnerapred.ast_analyzer import analyze_code_ast

code = """
import sqlite3
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
"""

results = analyze_code_ast(code)
for vuln in results:
    print(f"Type: {vuln['type']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Line: {vuln['line_number']}")
    print(f"Description: {vuln['description']}")
```

## Technical Details

### Machine Learning Algorithms

#### Classification Models
- **Logistic Regression** (default): Fast, interpretable binary classification
- **Random Forest**: Ensemble method for robust classification
- **XGBoost**: Gradient boosting for high-accuracy detection
- **SVM**: Support Vector Machines (optional)

#### Regression Models
- **Linear Regression** (default): Base model for urgency prediction
- **Ridge Regression**: L2 regularization for better generalization
- **Lasso Regression**: L1 regularization with feature selection
- **Random Forest Regressor**: Non-linear urgency prediction

### Feature Engineering

The system extracts **80+ features** from code:

#### Statistical Features (30+)
- Line count, function count, class count
- Code complexity metrics
- Keyword counts (SQL, network, file operations)
- String operations count
- Dangerous function detection (eval, exec, system)
- Comment ratio, docstring presence

#### TF-IDF Features (50)
- Term frequency-inverse document frequency
- Tokenized code representation
- N-gram analysis of code patterns

#### AST Features
- Function call patterns
- Variable assignment tracking
- Control flow structure
- Import statement analysis

### AST-Based Analysis

Advanced static analysis using Python's `ast` module:

- **Abstract Syntax Tree Parsing**: Semantic code understanding without execution
- **Context-Aware Detection**: Ignores comments/strings, analyzes actual code structure
- **Data Flow Tracking**: Tracks tainted variables from user input sources
- **Control Flow Analysis**: Detects conditional vs. unconditional vulnerabilities
- **False Positive Reduction**: Distinguishes between vulnerable and safe usage patterns
- **Multi-layered Detection**: Checks function calls, string operations, and data flow

### Pattern Detection

Regex-based detection of known vulnerability signatures:
- SQL injection patterns (string concatenation, f-strings in queries)
- Command injection patterns (shell=True, os.system)
- Code injection patterns (eval, exec, compile)
- Deserialization patterns (pickle.loads, marshal.loads)
- Hardcoded credentials (password=, api_key=)

### Risk Assessment

Multi-dimensional risk factor analysis:
- **Code Complexity**: LOW/MEDIUM/HIGH based on function count and nesting
- **Dangerous Functions**: NONE/PRESENT/HIGH based on eval, exec, system usage
- **Input Handling**: SAFE/UNVALIDATED/VALIDATED based on sanitization
- **Error Handling**: NONE/MINIMAL/PRESENT based on try/except blocks
- **Authentication**: UNKNOWN/WEAK/SECURE based on auth patterns

### Priority Levels

Urgency scores mapped to actionable priorities:
- 🔴 **CRITICAL** (80-100): Immediate action required within 24 hours
- 🟠 **HIGH** (60-79): Address within days
- 🟡 **MEDIUM** (40-59): Fix within weeks
- 🟢 **LOW** (0-39): Fix when convenient

## Model Performance

### Current Performance Metrics

Based on merged dataset (training_dataset.csv + cve_like_training.csv + real_cve_dataset.csv):

#### Vulnerability Classifier
- **Accuracy**: 100% (test set)
- **Precision**: 1.0000
- **Recall**: 1.0000
- **F1 Score**: 1.0000
- **ROC-AUC**: 1.0000

#### Urgency Predictor
- **R² Score**: 0.924 (92.4% variance explained)
- **MAE**: 7.14 points (average error)
- **RMSE**: 9.77 points (root mean squared error)

#### Detection Coverage
- **Detection Rate**: 100% on known vulnerability types
- **False Positives**: Near zero on safe code
- **Supported Vulnerabilities**: 9 major CWE categories

### Visualization

Generate comprehensive ML performance graphs:

```bash
# Generate all visualizations
python visualize_models.py

# Quick generation (skip learning curves)
python visualize_models.py --skip-learning-curves

# Train with Random Forest and generate all graphs including feature importance
python generate_all_graphs.py
```

**Generated visualizations** (saved to `visualizations/` directory):
- **confusion_matrix.png**: Classification confusion matrix
- **roc_curve.png**: ROC curve with AUC score
- **precision_recall_curve.png**: Precision-Recall curve
- **learning_curves.png**: Model performance vs training size
- **regression_performance.png**: Actual vs predicted urgency scores & residuals
- **metrics_comparison.png**: Train vs test metrics comparison
- **data_distribution.png**: Dataset class and urgency distribution
- **feature_importance.png**: Top 20 important features (for tree-based models)

See `visualizations/README.md` for detailed descriptions of each graph.

### Performance Improvements

See `PERFORMANCE_IMPROVEMENTS.md` for detailed optimization history.

**Before optimizations:**
- Detection Rate: ~33% (2/6 test cases)
- False Negatives: High

**After optimizations:**
- Detection Rate: 100% (6/6 test cases)
- Zero false positives
- Enhanced AST analysis
- Improved pattern coverage

## Testing

Run the test suite:

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_models.py

# Run with coverage
pytest tests/ --cov=vulnerapred
```

**Test coverage includes:**
- AST analyzer for all vulnerability types
- ML model training and prediction
- Feature extraction
- End-to-end integration tests
- Safe code validation (no false positives)

## Verification

Verify that models learn patterns (not just hardcoded rules):

```bash
# Verify learning capability
python verify_learning_fixed.py

# Run example workflow
python example.py
```

## Contributing

This is an academic project for CS/AI coursework. Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Known Limitations

- **Language Support**: Python only (future: multi-language support)
- **Context Awareness**: Limited to function-level analysis
- **False Positives**: Pattern detection may flag intentionally safe code
- **Dataset Bias**: Trained primarily on synthetic + CVE data

## Future Enhancements

- [ ] Support for more programming languages (JavaScript, Java, C++)
- [ ] Deep learning models (LSTM, Transformer-based)
- [ ] Integration with CI/CD pipelines
- [ ] Web-based dashboard
- [ ] Real-time code scanning
- [ ] Automated fix suggestions

## License

MIT License - See LICENSE file for details

## Acknowledgments

- BigVul dataset for real-world CVE examples
- NIST NVD for CVE classifications
- CWE (Common Weakness Enumeration) for vulnerability taxonomy

## Contact

For questions or issues, please open a GitHub issue or contact the project maintainer.
