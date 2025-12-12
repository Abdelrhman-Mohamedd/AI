"""
VulneraPred Web Application
Modern web-based GUI using Flask
"""

from flask import Flask, render_template, request, jsonify
import sys
import os
from datetime import datetime
import traceback

# Add parent directory to path to import vulnerapred modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from predict import detect_vulnerability_patterns, predict_code, load_models, calculate_risk_factors
from vulnerapred.features import CodeFeatureExtractor
import ast as ast_module

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global variables for models
classifier = None
predictor = None
feature_extractor = None
models_loaded = False


def initialize_models():
    """Load ML models on startup"""
    global classifier, predictor, feature_extractor, models_loaded
    try:
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        classifier, predictor, feature_extractor = load_models(model_dir)
        models_loaded = True
        print("✓ Models loaded successfully")
    except Exception as e:
        print(f"✗ Error loading models: {str(e)}")
        models_loaded = False


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html', models_loaded=models_loaded)


@app.route('/api/status')
def get_status():
    """Get server status"""
    return jsonify({
        'models_loaded': models_loaded,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    """Analyze code for vulnerabilities"""
    if not models_loaded:
        return jsonify({
            'success': False,
            'error': 'Models not loaded. Please restart the server.'
        }), 503
    
    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        
        if not code:
            return jsonify({
                'success': False,
                'error': 'No code provided'
            }), 400
        
        start_time = datetime.now()
        
        # Check if valid Python code
        is_valid_python = True
        syntax_error_msg = None
        
        try:
            ast_module.parse(code)
        except SyntaxError as e:
            is_valid_python = False
            syntax_error_msg = str(e)
        except Exception:
            is_valid_python = False
            syntax_error_msg = "Unable to parse - not valid Python code"
        
        # If not valid Python, return error
        if not is_valid_python:
            analysis_time = (datetime.now() - start_time).total_seconds()
            return jsonify({
                'success': True,
                'is_valid_python': False,
                'syntax_error': syntax_error_msg,
                'analysis_time': analysis_time
            })
        
        # Perform ML prediction
        is_vulnerable, vulnerability_score, urgency_score = predict_code(
            code, classifier, predictor, feature_extractor, threshold=0.5
        )
        
        # Detect vulnerability patterns
        vulnerabilities = detect_vulnerability_patterns(code)
        
        # Extract statistics
        stats = feature_extractor.extract_statistical_features(code)
        
        # Filter out syntax_error from vulnerabilities
        vulnerabilities = [v for v in vulnerabilities if v.get('type', '').lower() != 'syntax_error']
        
        # If patterns detected, boost vulnerability score
        if vulnerabilities and not is_vulnerable:
            is_vulnerable = True
            vulnerability_score = max(vulnerability_score, 0.85)
        
        # Calculate risk factors
        risk_factors = calculate_risk_factors(code, stats)
        
        # Calculate analysis time
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        # Convert numpy types to native Python types for JSON serialization
        is_vulnerable = bool(is_vulnerable)
        vulnerability_score = float(vulnerability_score)
        urgency_score = float(urgency_score)
        
        # Build response
        response = {
            'success': True,
            'is_valid_python': True,
            'is_vulnerable': is_vulnerable,
            'confidence': vulnerability_score * 100,
            'urgency_score': urgency_score,
            'analysis_time': analysis_time,
            'statistics': {
                'code_length': int(stats.get('code_length', 0)),
                'line_count': int(stats.get('line_count', 0)),
                'sql_keywords': int(stats.get('sql_keywords', 0)),
                'dangerous_functions': int(stats.get('dangerous_functions', 0)),
                'string_operations': int(stats.get('string_operations', 0)),
                'network_operations': int(stats.get('network_operations', 0)),
                'file_operations': int(stats.get('file_operations', 0))
            },
            'vulnerabilities': [
                {
                    'type': v.get('type', 'Unknown'),
                    'severity': v.get('severity', 'MEDIUM'),
                    'description': v.get('description', 'No description'),
                    'line': v.get('line', 'N/A'),
                    'detection': 'AST' if v.get('pattern') == 'AST Analysis' else 'Pattern'
                }
                for v in vulnerabilities
            ],
            'risk_factors': risk_factors,
            'recommendations': get_recommendations(is_vulnerable, vulnerabilities)
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in analyze_code: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }), 500


def get_recommendations(is_vulnerable, vulnerabilities):
    """Get recommendations based on vulnerabilities"""
    recommendations = []
    
    if is_vulnerable:
        vuln_types = set(v.get('type', '') for v in vulnerabilities)
        
        if any('SQL Injection' in t for t in vuln_types):
            recommendations.append({
                'category': 'SQL Injection Prevention',
                'items': [
                    'Use parameterized queries instead of string concatenation',
                    "Example: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                    'Validate and sanitize all user inputs'
                ]
            })
        
        if any('Command Injection' in t for t in vuln_types):
            recommendations.append({
                'category': 'Command Injection Prevention',
                'items': [
                    'Avoid shell=True in subprocess calls',
                    "Use argument lists: subprocess.run(['ping', host])",
                    'Validate and whitelist allowed commands'
                ]
            })
        
        if any('Code Injection' in t or 'eval' in t.lower() or 'exec' in t.lower() for t in vuln_types):
            recommendations.append({
                'category': 'Code Injection Prevention',
                'items': [
                    'Never use eval() or exec() with user input',
                    'Use ast.literal_eval() for safe data parsing',
                    'Implement strict input validation'
                ]
            })
        
        if any('XSS' in t or 'Cross-Site' in t for t in vuln_types):
            recommendations.append({
                'category': 'XSS Prevention',
                'items': [
                    'Use template engines with auto-escaping',
                    'Sanitize all user input before rendering',
                    'Implement Content Security Policy (CSP)'
                ]
            })
        
        if any('Path Traversal' in t for t in vuln_types):
            recommendations.append({
                'category': 'Path Traversal Prevention',
                'items': [
                    'Validate file paths against allowed directories',
                    'Use os.path.abspath() and check path prefix',
                    'Never concatenate user input with file paths'
                ]
            })
        
        recommendations.append({
            'category': 'General Security',
            'items': [
                'Review and fix all detected vulnerabilities immediately',
                'Implement comprehensive input validation',
                'Follow OWASP Top 10 guidelines',
                'Keep all dependencies updated'
            ]
        })
    else:
        recommendations.append({
            'category': 'Best Practices',
            'items': [
                'Code appears secure - continue following best practices',
                'Perform regular security audits',
                'Keep dependencies up to date',
                'Monitor for new vulnerability patterns',
                'Use security linters in CI/CD pipeline'
            ]
        })
    
    return recommendations


if __name__ == '__main__':
    print("="*60)
    print("VulneraPred Web Application")
    print("="*60)
    print("\nInitializing models...")
    initialize_models()
    print("\nStarting Flask server...")
    print("Open your browser and navigate to: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("="*60)
    app.run(debug=True, host='0.0.0.0', port=5000)
