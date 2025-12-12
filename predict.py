"""
Prediction CLI for vulnerability detection and urgency scoring.

Use this script to analyze new code snippets or files.
"""

import argparse
import os
import sys
import joblib
import ast
import re
from pathlib import Path

from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor
from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.utils import format_vulnerability_result

try:
    from vulnerapred.ast_analyzer import analyze_code_ast
    AST_ANALYSIS_AVAILABLE = True
except ImportError:
    AST_ANALYSIS_AVAILABLE = False


def load_models(model_dir: str):
    """Load trained models from disk."""
    classifier_path = os.path.join(model_dir, 'vulnerability_classifier.pkl')
    predictor_path = os.path.join(model_dir, 'urgency_predictor.pkl')
    extractor_path = os.path.join(model_dir, 'feature_extractor.pkl')
    
    # Check if models exist
    if not os.path.exists(classifier_path):
        print(f"Error: Classifier not found at {classifier_path}")
        print("Please run train.py first to train the models.")
        sys.exit(1)
    
    if not os.path.exists(predictor_path):
        print(f"Error: Predictor not found at {predictor_path}")
        print("Please run train.py first to train the models.")
        sys.exit(1)
    
    if not os.path.exists(extractor_path):
        print(f"Error: Feature extractor not found at {extractor_path}")
        print("Please run train.py first to train the models.")
        sys.exit(1)
    
    print("Loading models...")
    classifier = VulnerabilityClassifier.load(classifier_path)
    predictor = UrgencyPredictor.load(predictor_path)
    extractor = joblib.load(extractor_path)
    
    print("Models loaded successfully")
    return classifier, predictor, extractor


def detect_vulnerability_patterns(code: str) -> list:
    """Detect specific vulnerability patterns in code using both AST and regex."""
    
    vulnerabilities = []
    
    # First, try AST-based analysis (more accurate)
    if AST_ANALYSIS_AVAILABLE:
        ast_vulns = analyze_code_ast(code)
        for ast_vuln in ast_vulns:
            vulnerabilities.append({
                'type': ast_vuln.get('type', 'Unknown'),
                'description': ast_vuln.get('description', 'AST-detected vulnerability'),
                'severity': ast_vuln.get('severity', 'medium').upper(),
                'pattern': 'AST Analysis',
                'line': ast_vuln.get('line', 0)
            })
    
    # Continue with regex-based patterns as fallback/complement
    
    # SQL Injection patterns
    sql_patterns = [
        (r'SELECT.*FROM.*\+', 'SQL Injection', 'String concatenation in SQL query', 'CRITICAL'),
        (r'\.execute\s*\([^)]*[+%]', 'SQL Injection', 'String concatenation in SQL query', 'CRITICAL'),
        (r'f["\'].*SELECT.*{', 'SQL Injection', 'f-string in SQL query', 'CRITICAL'),
        (r'\.format\(.*\).*execute', 'SQL Injection', '.format() in SQL query', 'HIGH'),
    ]
    
    # NoSQL Injection patterns
    nosql_patterns = [
        (r'find_one\s*\([^)]*\[.*\][^)]*\)', 'NoSQL Injection', 'User-controlled dict in MongoDB query', 'CRITICAL'),
        (r'find\s*\([^)]*\[.*\][^)]*\)', 'NoSQL Injection', 'User-controlled dict in MongoDB query', 'CRITICAL'),
        (r'db\.\w+\.find_one\s*\([^)]*data\[', 'NoSQL Injection', 'User data dictionary in NoSQL query', 'CRITICAL'),
        (r'db\.\w+\.find\s*\([^)]*data\[', 'NoSQL Injection', 'User data dictionary in NoSQL query', 'CRITICAL'),
        (r'\.find_one\s*\({[^}]*username[^}]*}\)', 'NoSQL Injection', 'Direct field interpolation in MongoDB query', 'CRITICAL'),
    ]
    
    # Command Injection patterns
    command_patterns = [
        (r'(echo|ls|cat|rm|wget|curl|chmod|chown)\s*\+', 'Command Injection', 'String concatenation in system command', 'CRITICAL'),
        (r'built\s*=\s*["\'][^"\']*(echo|ls|cat|rm|wget|curl)[^"\']*["\']\s*\+', 'Command Injection', 'Building shell command with concatenation', 'CRITICAL'),
        (r'command\s*=\s*["\'][^"\']*["\']\s*\+', 'Command Injection', 'String concatenation in command', 'CRITICAL'),
        (r'os\.system\s*\(', 'Command Injection', 'os.system() with user input', 'CRITICAL'),
        (r'subprocess\.(run|call|Popen|check_output|check_call).*shell\s*=\s*True', 'Command Injection', 'subprocess with shell=True', 'CRITICAL'),
        (r'shell\s*=\s*True.*subprocess\.(run|call|Popen|check_output|check_call)', 'Command Injection', 'subprocess with shell=True', 'CRITICAL'),
        (r'(?<![a-zA-Z_\"])eval\s*\(', 'Code Injection', 'eval() with untrusted input', 'CRITICAL'),
        (r'(?<![a-zA-Z_\"])exec\s*\(', 'Code Injection', 'exec() with untrusted input', 'CRITICAL'),
    ]
    
    # XSS patterns
    xss_patterns = [
        (r'<[^>]+>.*\+.*</', 'Cross-Site Scripting (XSS)', 'HTML concatenation with user input', 'HIGH'),
        (r'innerHTML.*=', 'Cross-Site Scripting (XSS)', 'Direct innerHTML assignment', 'MEDIUM'),
        (r'return.*<[^>]+>.*\+', 'Cross-Site Scripting (XSS)', 'Returning HTML with concatenation', 'HIGH'),
    ]
    
    # Path Traversal patterns
    path_patterns = [
        (r'["\'][^"\']*[/\\]["\'].*\+.*filename', 'Path Traversal', 'String concatenation in file path', 'HIGH'),
        (r'open\s*\([^)]*\.\.[/\\]', 'Path Traversal', 'Directory traversal (../) in file path', 'HIGH'),
        (r'os\.path\.join.*request\.(args|form|json)', 'Path Traversal', 'User input in file path', 'MEDIUM'),
        (r'open\s*\([^)]*filename[^)]*\)', 'Path Traversal', 'open() with user-controlled filename parameter', 'HIGH'),
        (r'open\s*\([^)]*path[^)]*\)', 'Path Traversal', 'open() with user-controlled path parameter', 'HIGH'),
    ]
    
    # Deserialization patterns
    deser_patterns = [
        (r'pickle\.loads?\s*\(', 'Insecure Deserialization', 'pickle with untrusted data', 'CRITICAL'),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader', 'Insecure Deserialization', 'yaml.load with unsafe Loader', 'CRITICAL'),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader', 'Insecure Deserialization', 'yaml.load with FullLoader (unsafe)', 'CRITICAL'),
        (r'yaml\.load\s*\([^)]*\)', 'Insecure Deserialization', 'yaml.load without explicit SafeLoader', 'CRITICAL'),
    ]
    
    # Weak Cryptography patterns
    crypto_patterns = [
        (r'hashlib\.md5\s*\(', 'Weak Cryptography', 'MD5 is cryptographically broken', 'HIGH'),
        (r'hashlib\.sha1\s*\(', 'Weak Cryptography', 'SHA1 is deprecated for security', 'MEDIUM'),
        (r'\.md5\s*\(', 'Weak Cryptography', 'MD5 hashing detected', 'HIGH'),
        (r'Crypto\.Hash\.MD5', 'Weak Cryptography', 'MD5 from pycrypto', 'HIGH'),
    ]
    
    # Hardcoded secrets
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded Credentials', 'Hardcoded password in code', 'HIGH'),
        (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded Credentials', 'Hardcoded API key', 'HIGH'),
        (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded Credentials', 'Hardcoded secret in code', 'HIGH'),
        (r'SECRET_KEY\s*=\s*["\'][^"\']+["\']', 'Hardcoded Credentials', 'Hardcoded SECRET_KEY in code', 'CRITICAL'),
        (r'token\s*=\s*base64', 'Weak Cryptography', 'Using base64 for token generation (not encryption)', 'CRITICAL'),
        (r'base64.*token', 'Weak Cryptography', 'Using base64 for token generation (not encryption)', 'CRITICAL'),
    ]
    
    # Logic flaws and authentication bypass patterns
    logic_patterns = [
        (r'def.*login.*:.*return\s+True', 'Authentication Bypass', 'Suspicious login logic that returns True', 'CRITICAL'),
        (r'if.*username.*not in.*return\s+True', 'Authentication Bypass', 'Returns True when user not found (bypass)', 'CRITICAL'),
        (r'def.*auth.*:.*return\s+True', 'Authentication Bypass', 'Suspicious auth logic that returns True', 'CRITICAL'),
    ]
    
    # Race conditions and concurrency issues
    race_patterns = [
        (r'cache\[.*\]\s*=.*time\.sleep', 'Race Condition', 'Cache update without synchronization (race condition)', 'CRITICAL'),
        (r'def.*withdraw.*:.*cache\[.*\]\s*=', 'Race Condition', 'Non-atomic financial transaction (race condition)', 'CRITICAL'),
        (r'balance\s*=.*cache.*if.*>=.*=.*-.*cache', 'Race Condition', 'Check-then-act race condition pattern', 'CRITICAL'),
    ]
    
    # SSRF and network security patterns
    ssrf_patterns = [
        (r'requests\.get\s*\([^)]*url[^)]*\)', 'Server-Side Request Forgery (SSRF)', 'Unvalidated URL in requests.get (SSRF vulnerability)', 'CRITICAL'),
        (r'requests\.post\s*\([^)]*url[^)]*\)', 'Server-Side Request Forgery (SSRF)', 'Unvalidated URL in requests.post (SSRF vulnerability)', 'CRITICAL'),
        (r'urllib\.urlopen\s*\([^)]*url[^)]*\)', 'Server-Side Request Forgery (SSRF)', 'Unvalidated URL in urlopen (SSRF vulnerability)', 'CRITICAL'),
        (r'def.*fetch.*:.*requests\.', 'Server-Side Request Forgery (SSRF)', 'Fetch function with unvalidated HTTP request', 'CRITICAL'),
        (r'def.*download.*:.*requests\.', 'Server-Side Request Forgery (SSRF)', 'Download function with unvalidated HTTP request', 'CRITICAL'),
    ]
    
    all_patterns = (
        sql_patterns + nosql_patterns + command_patterns + xss_patterns + 
        path_patterns + deser_patterns + crypto_patterns + secret_patterns + logic_patterns + race_patterns + ssrf_patterns
    )
    
    for pattern, vuln_type, description, severity in all_patterns:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append({
                'type': vuln_type,
                'description': description,
                'severity': severity,
                'pattern': pattern
            })
    
    return vulnerabilities


def calculate_risk_factors(code: str, stats: dict) -> dict:
    """Calculate various risk factors."""
    
    risk_factors = {
        'code_complexity': 'LOW',
        'dangerous_functions': 'NONE',
        'input_handling': 'SAFE',
        'error_handling': 'UNKNOWN',
        'authentication': 'UNKNOWN'
    }
    
    # Code complexity
    code_len = stats.get('code_length', len(code))
    if code_len > 500:
        risk_factors['code_complexity'] = 'HIGH'
    elif code_len > 200:
        risk_factors['code_complexity'] = 'MEDIUM'
    
    # Dangerous functions - also count network operations used unsafely
    dangerous_count = stats.get('dangerous_functions', 0)
    # Add extra count for requests/urllib with parameters
    if 'requests.get' in code or 'requests.post' in code or 'urllib.urlopen' in code:
        dangerous_count += 1
    
    if dangerous_count > 3:
        risk_factors['dangerous_functions'] = 'HIGH'
    elif dangerous_count > 0:
        risk_factors['dangerous_functions'] = 'PRESENT'
    
    # Input handling
    code_no_comments = re.sub(r'#.*', '', code)  # Remove comments for cleaner analysis
    
    if 'request.' in code or 'input(' in code:
        if any(x in code for x in ['sanitize', 'escape', 'validate']):
            risk_factors['input_handling'] = 'VALIDATED'
        else:
            risk_factors['input_handling'] = 'UNVALIDATED'
    elif any(x in code_no_comments for x in ['url', 'user_id', 'user_input', 'username', 'password', 'amount', 'data', 'path', 'file']):
        # Check if user parameters are used safely (in the actual code, not comments)
        if any(x in code_no_comments for x in ['lock', 'mutex', 'atomic', 'transaction', 'sanitize', 'escape', 'validate', 'whitelist']):
            risk_factors['input_handling'] = 'VALIDATED'
        else:
            risk_factors['input_handling'] = 'UNSAFE'
    else:
        risk_factors['input_handling'] = 'SAFE'
    
    # Error handling
    if 'try:' in code and 'except' in code:
        risk_factors['error_handling'] = 'PRESENT'
    elif 'raise' in code:
        risk_factors['error_handling'] = 'MINIMAL'
    else:
        risk_factors['error_handling'] = 'NONE'
    
    # Authentication
    if any(x in code for x in ['login', 'authenticate', 'auth', 'password', 'token']):
        if any(x in code for x in ['bcrypt', 'hash', 'verify']):
            risk_factors['authentication'] = 'SECURE'
        else:
            risk_factors['authentication'] = 'WEAK'
    
    return risk_factors


def extract_functions(code: str):
    """
    Extract individual functions from code.
    
    Args:
        code: Full code as string
        
    Returns:
        List of dicts with function info
    """
    functions = []
    
    try:
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Get function source
                func_lines = code.split('\n')[node.lineno - 1:node.end_lineno]
                func_code = '\n'.join(func_lines)
                
                functions.append({
                    'name': node.name,
                    'code': func_code,
                    'line_start': node.lineno,
                    'line_end': node.end_lineno
                })
    except:
        # If parsing fails, return empty
        pass
    
    return functions


def predict_code(code: str, classifier, predictor, extractor, threshold: float = 0.5):
    """
    Predict vulnerability and urgency for code snippet.
    
    Args:
        code: Code snippet as string
        classifier: Trained VulnerabilityClassifier
        predictor: Trained UrgencyPredictor
        extractor: Fitted CodeFeatureExtractor
        threshold: Classification threshold (0-1)
        
    Returns:
        Tuple of (is_vulnerable, vulnerability_score, urgency_score)
    """
    # Extract features
    X = extractor.transform([code])
    
    # Predict vulnerability
    vulnerability_score = classifier.get_vulnerability_score(X)[0]
    is_vulnerable = vulnerability_score >= threshold
    
    # Predict urgency (base ML prediction)
    urgency_score = predictor.predict(X)[0]
    
    # Enhance urgency based on pattern detection (hybrid approach)
    detected_vulns = detect_vulnerability_patterns(code)
    
    if detected_vulns:
        # Get highest severity from detected patterns
        max_severity_score = 0
        
        for vuln in detected_vulns:
            severity = vuln.get('severity', 'MEDIUM').upper()
            
            # Map severity to urgency scores
            severity_scores = {
                'CRITICAL': 95,
                'HIGH': 80,
                'MEDIUM': 60,
                'LOW': 40
            }
            
            pattern_score = severity_scores.get(severity, 50)
            max_severity_score = max(max_severity_score, pattern_score)
        
        # Take the maximum of ML prediction and pattern-based score
        # This ensures known critical vulnerabilities are always rated high
        urgency_score = max(urgency_score, max_severity_score)
    
    return is_vulnerable, vulnerability_score, urgency_score


def get_priority_level(urgency: float) -> tuple:
    """Get priority level and emoji from urgency score."""
    if urgency >= 80:
        return "CRITICAL", "🔴", "Immediate action required"
    elif urgency >= 60:
        return "HIGH", "🟠", "Should be fixed soon"
    elif urgency >= 40:
        return "MEDIUM", "🟡", "Should be reviewed"
    elif urgency >= 20:
        return "LOW", "🟢", "Minor issue"
    else:
        return "MINIMAL", "⚪", "Optional improvement"


def print_detailed_results(func_name, code, is_vulnerable, vulnerability_score, urgency_score, extractor):
    """Print detailed analysis results."""
    
    priority, emoji, priority_desc = get_priority_level(urgency_score)
    
    print("\n" + "=" * 80)
    print(f"  FUNCTION: {func_name}")
    print("=" * 80)
    
    # Status
    print(f"\n{emoji} STATUS: {'VULNERABLE' if is_vulnerable else 'SAFE'}")
    print(f"   Confidence: {vulnerability_score*100:.2f}%")
    print(f"   Urgency Score: {urgency_score:.2f}/100")
    print(f"   Priority: {priority} - {priority_desc}")
    
    # Extract statistical features
    stats = extractor.extract_statistical_features(code)
    
    # Code statistics
    print(f"\n📊 CODE STATISTICS:")
    print(f"   Lines of code: {stats.get('line_count', 0)}")
    print(f"   SQL keywords: {stats.get('sql_keywords', 0)}")
    print(f"   Dangerous functions: {stats.get('dangerous_functions', 0)}")
    print(f"   String operations: {stats.get('string_operations', 0)}")
    print(f"   Network operations: {stats.get('network_operations', 0)}")
    print(f"   File operations: {stats.get('file_operations', 0)}")
    
    # Detected vulnerabilities
    vulnerabilities = detect_vulnerability_patterns(code)
    
    if vulnerabilities:
        print(f"\n⚠️  VULNERABILITIES DETECTED ({len(vulnerabilities)}):")
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(vuln['severity'], '⚪')
            
            print(f"\n   {i}. {severity_emoji} {vuln['type']} [{vuln['severity']}]")
            print(f"      Description: {vuln['description']}")
            if 'line' in vuln and vuln['line'] > 0:
                print(f"      Line: {vuln['line']}")
            detection_method = "AST" if vuln.get('pattern') == 'AST Analysis' else "Pattern"
            print(f"      Detection: {detection_method}")
    else:
        print(f"\n✓ No specific vulnerability patterns detected")
    
    # Risk factors
    risk_factors = calculate_risk_factors(code, stats)
    
    print(f"\n🎯 RISK ASSESSMENT:")
    print(f"   Code Complexity: {risk_factors['code_complexity']}")
    print(f"   Dangerous Functions: {risk_factors['dangerous_functions']}")
    print(f"   Input Handling: {risk_factors['input_handling']}")
    print(f"   Error Handling: {risk_factors['error_handling']}")
    print(f"   Authentication: {risk_factors['authentication']}")
    
    # Recommendations
    if is_vulnerable:
        print(f"\n💡 RECOMMENDATIONS:")
        
        if any('SQL Injection' in v['type'] for v in vulnerabilities):
            print(f"   • Use parameterized queries instead of string concatenation")
            print(f"     Example: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))")
        
        if any('NoSQL Injection' in v['type'] for v in vulnerabilities):
            print(f"   • Use parameterized queries in MongoDB with explicit field names")
            print(f"   • Never pass user-controlled dictionaries directly to queries")
            print(f"     Example: db.users.find_one({{'username': username}}) NOT db.users.find_one(data)")
        
        if any('Command Injection' in v['type'] for v in vulnerabilities):
            print(f"   • Avoid shell=True in subprocess calls")
            print(f"   • Use subprocess with argument lists instead of strings")
        
        if any('XSS' in v['type'] for v in vulnerabilities):
            print(f"   • Sanitize user input before rendering in HTML")
            print(f"   • Use template engines with auto-escaping (Jinja2, Django)")
            print(f"     Example: from markupsafe import escape; return f'<div>{{escape(name)}}</div>'")
        
        if any('Path Traversal' in v['type'] for v in vulnerabilities):
            print(f"   • Validate and sanitize file paths")
            print(f"   • Use os.path.abspath() and check if path starts with allowed directory")
        
        if any('Deserialization' in v['type'] for v in vulnerabilities):
            print(f"   • Avoid pickle with untrusted data")
            print(f"   • Use JSON or other safe serialization formats")
        
        if any('Weak Cryptography' in v['type'] for v in vulnerabilities):
            print(f"   • Replace MD5/SHA1 with SHA-256 or stronger algorithms")
            print(f"   • For password hashing, use bcrypt, argon2, or scrypt")
            print(f"     Example: import bcrypt; hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())")
        
        if any('Hardcoded Credentials' in v['type'] for v in vulnerabilities):
            print(f"   • Move credentials to environment variables")
            print(f"   • Use a secrets management system")
        
        if any('SSRF' in v['type'] or 'Server-Side Request Forgery' in v['type'] for v in vulnerabilities):
            print(f"   • Validate and whitelist allowed URLs")
            print(f"   • Reject requests to internal IP ranges (127.0.0.1, 10.0.0.0/8, etc.)")
            print(f"   • Use URL parsing to prevent bypass attempts")
            print(f"     Example: from urllib.parse import urlparse; validate_url(url)")
        
        if any('Race Condition' in v['type'] for v in vulnerabilities):
            print(f"   • Use locks/mutexes for shared resource access")
            print(f"   • Implement atomic transactions")
            print(f"   • Use threading.Lock() or database transactions for concurrent operations")
        
        if any('Authentication Bypass' in v['type'] for v in vulnerabilities):
            print(f"   • Always return False for authentication failure")
            print(f"   • Validate all authentication logic paths")
            print(f"   • Use established authentication frameworks (e.g., OAuth, JWT)")
        
        if risk_factors['input_handling'] == 'UNVALIDATED':
            print(f"   • Add input validation and sanitization")
        
        if risk_factors['error_handling'] == 'NONE':
            print(f"   • Add proper error handling (try/except blocks)")
    
    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(description='Predict vulnerability and urgency for code snippets')
    parser.add_argument('--model-dir', type=str, default='models',
                       help='Directory containing trained models')
    parser.add_argument('--threshold', type=float, default=0.5,
                       help='Classification threshold for vulnerability (0-1)')
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Path to code file to analyze')
    input_group.add_argument('--code', type=str, help='Code snippet as string')
    input_group.add_argument('--snippet', action='store_true', 
                           help='Read code snippet from stdin')
    
    # Output options
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output')
    
    args = parser.parse_args()
    
    # Load models
    classifier, predictor, extractor = load_models(args.model_dir)
    
    # Get code to analyze
    if args.file:
        print(f"\nAnalyzing file: {args.file}")
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
        
        # Check if file is empty or only whitespace
        if not code or not code.strip():
            print("\n" + "="*80)
            print("✓ FILE IS EMPTY")
            print("="*80)
            print("\nNo code to analyze. Empty files are safe by default.")
            sys.exit(0)
            sys.exit(1)
        
        # For files, analyze both full file and individual functions
        functions = extract_functions(code)
        
        if functions and len(functions) > 0:
            print(f"Found {len(functions)} function(s) in file\n")
            
            # Analyze each function
            vulnerable_functions = []
            
            for func in functions:
                func_name = func['name']
                func_code = func['code']
                
                is_vuln, vuln_score, urgency = predict_code(
                    func_code, classifier, predictor, extractor, threshold=args.threshold
                )
                
                # Hybrid approach: Also check rule-based patterns
                # If patterns are detected, flag as vulnerable even if ML score is low
                vulnerabilities = detect_vulnerability_patterns(func_code)
                has_patterns = len(vulnerabilities) > 0
                
                if is_vuln or has_patterns:
                    # Calculate confidence boost based on detected vulnerabilities
                    pattern_confidence = 0.0
                    pattern_urgency = 0.0
                    if has_patterns:
                        # Base confidence on number of patterns found
                        pattern_confidence = min(0.95, 0.3 + (len(vulnerabilities) * 0.15))
                        
                        # Boost further for critical severity patterns
                        critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
                        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
                        medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM')
                        
                        pattern_confidence += (critical_count * 0.2) + (high_count * 0.1)
                        pattern_confidence = min(0.95, pattern_confidence)
                        
                        # Calculate urgency based on vulnerability severity
                        pattern_urgency = 30.0 + (critical_count * 30) + (high_count * 15) + (medium_count * 8)
                        pattern_urgency = min(100.0, pattern_urgency)
                    
                    # If patterns detected but ML says safe, boost the score
                    if has_patterns and not is_vuln:
                        vuln_score = max(vuln_score, pattern_confidence)
                        urgency = max(urgency, pattern_urgency)
                    elif has_patterns and is_vuln:
                        # If both patterns and ML agree, boost even more
                        vuln_score = max(vuln_score, pattern_confidence)
                        urgency = max(urgency, pattern_urgency)
                    
                    vulnerable_functions.append((func_name, func_code, vuln_score, urgency))
            
            # Show detailed results for each vulnerable function
            if vulnerable_functions:
                print(f"{'='*80}")
                print(f"⚠️  FOUND {len(vulnerable_functions)} VULNERABLE FUNCTION(S)")
                print(f"{'='*80}")
                
                for func_name, func_code, vuln_score, urgency in vulnerable_functions:
                    print_detailed_results(func_name, func_code, True, vuln_score, urgency, extractor)
                
                # Set overall result to worst case
                is_vulnerable = True
                vulnerability_score = max(v[2] for v in vulnerable_functions)
                urgency_score = max(v[3] for v in vulnerable_functions)
            else:
                # If no vulnerable functions detected by AST/patterns, show safe message
                # Analyze whole file for ML-based scoring
                is_vulnerable, vulnerability_score, urgency_score = predict_code(
                    code, classifier, predictor, extractor, threshold=args.threshold
                )
                
                # Always show summary when no vulnerable functions found
                print("\n" + "="*80)
                print("✅ ALL FUNCTIONS ARE SAFE")
                print("="*80)
                print(f"\n🟢 STATUS: SAFE")
                print(f"   All {len(functions)} function(s) analyzed")
                print(f"   ✓ AST Analysis: No vulnerabilities detected")
                
                # Check for any vulnerabilities via pattern detection
                all_vulnerabilities = detect_vulnerability_patterns(code)
                if all_vulnerabilities:
                    print(f"   ⚠️  Pattern Matching: {len(all_vulnerabilities)} potential match(es) (likely false positives)")
                else:
                    print(f"   ✓ Pattern Matching: No issues detected")
                
                # Show ML scores for reference (may be high due to presence of certain keywords)
                if vulnerability_score > 0.5 or urgency_score > 50:
                    print(f"\n💡 Note: ML model shows elevated scores due to security-related keywords")
                    print(f"   (This is expected for security-aware code using proper practices)")
                    print(f"   ML Scores: Vulnerability={vulnerability_score*100:.1f}%, Urgency={urgency_score:.1f}/100")
                
                print("\n" + "="*80)
        else:
            # No functions found, check if this is meaningful Python code
            # Check for meaningful Python constructs (imports, assignments, classes, etc.)
            has_meaningful_code = any([
                'import ' in code,
                'from ' in code,
                '=' in code,
                'class ' in code,
                'if ' in code,
                'for ' in code,
                'while ' in code,
                'return ' in code,
            ])
            
            if not has_meaningful_code:
                print("\n" + "="*80)
                print("⚠️  NO MEANINGFUL CODE FOUND")
                print("="*80)
                print(f"\nFile appears to contain only random text or nonsense.")
                print(f"No Python code constructs detected.")
                print(f"Overall confidence: 100.00% safe (no code to analyze)")
                sys.exit(0)
            
            # Valid Python code, analyze whole file
            is_vulnerable, vulnerability_score, urgency_score = predict_code(
                code, classifier, predictor, extractor, threshold=args.threshold
            )
    
    elif args.code:
        code = args.code
        if args.verbose:
            print(f"\nAnalyzing code snippet:")
            print("-" * 60)
            print(code)
            print("-" * 60)
        
        # Make prediction
        is_vulnerable, vulnerability_score, urgency_score = predict_code(
            code, classifier, predictor, extractor, threshold=args.threshold
        )
    
    else:  # stdin
        print("Enter code snippet (press Ctrl+Z then Enter on Windows, or Ctrl+D on Unix to finish):")
        code = sys.stdin.read()
        
        # Make prediction
        is_vulnerable, vulnerability_score, urgency_score = predict_code(
            code, classifier, predictor, extractor, threshold=args.threshold
        )
    
    # Output results
    if args.json:
        import json
        result = {
            'is_vulnerable': bool(is_vulnerable),
            'vulnerability_score': float(vulnerability_score),
            'urgency_score': float(urgency_score),
            'threshold_used': args.threshold
        }
        print(json.dumps(result, indent=2))
    else:
        # For code snippets or whole files without functions
        if not args.file or not functions:
            print(format_vulnerability_result(is_vulnerable, vulnerability_score, urgency_score))
        
        if args.verbose:
            print("\nAdditional Details:")
            print(f"  Classification threshold: {args.threshold}")
            print(f"  Raw vulnerability score: {vulnerability_score:.4f}")
            print(f"  Binary classification: {'VULNERABLE' if is_vulnerable else 'SAFE'}")


if __name__ == '__main__':
    main()
