"""
Enhanced CVE-like dataset generator.

Generates realistic vulnerable code patterns based on real CVE classifications
and OWASP Top 10 vulnerabilities. This is a better synthetic dataset than
the basic generator, while we work on getting the Big-Vul dataset.

This generator creates code patterns that closely match real-world CVEs.
"""

import random
import pandas as pd
from typing import List, Tuple


# Real CVE-inspired vulnerable patterns
REAL_CVE_PATTERNS = {
    'sql_injection': [
        # CWE-89: SQL Injection
        '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id=" + str(user_id)
    cursor.execute(query)
    return cursor.fetchone()''',
        
        '''def login(username, password):
    sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(sql).fetchone()''',
        
        '''def search_products(category):
    query = "SELECT * FROM products WHERE category='" + category + "'"
    cursor.execute(query)''',
        
        '''def update_email(user_id, email):
    query = f"UPDATE users SET email='{email}' WHERE id={user_id}"
    cursor.execute(query)''',
    ],
    
    'command_injection': [
        # CWE-78: OS Command Injection
        '''def backup_file(filename):
    os.system(f"tar -czf backup.tar.gz {filename}")''',
        
        '''def ping_host(hostname):
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True)
    return result.stdout''',
        
        '''def convert_image(input_file, output_file):
    cmd = f"convert {input_file} {output_file}"
    os.system(cmd)''',
        
        '''def download_url(url):
    subprocess.call(f"wget {url}", shell=True)''',
    ],
    
    'xss': [
        # CWE-79: Cross-site Scripting
        '''def display_comment(comment):
    return f"<div class='comment'>{comment}</div>"''',
        
        '''def render_user_profile(name, bio):
    html = f"<h1>{name}</h1><p>{bio}</p>"
    return html''',
        
        '''def search_results(query):
    return f"<div>Results for: {query}</div>"''',
        
        '''def show_error(error_msg):
    return "<div class='error'>" + error_msg + "</div>"''',
    ],
    
    'path_traversal': [
        # CWE-22: Path Traversal
        '''def read_file(filename):
    with open(f"uploads/{filename}", 'r') as f:
        return f.read()''',
        
        '''def load_template(template_name):
    path = "templates/" + template_name
    return open(path).read()''',
        
        '''def get_log_file(log_name):
    log_path = f"/var/logs/{log_name}"
    with open(log_path) as f:
        return f.read()''',
        
        '''def include_file(file_path):
    return open(file_path, 'r').read()''',
    ],
    
    'code_injection': [
        # CWE-94: Code Injection
        '''def execute_formula(formula):
    result = eval(formula)
    return result''',
        
        '''def run_user_code(code):
    exec(code)''',
        
        '''def parse_expression(expr):
    return eval(f"calculate({expr})")''',
        
        '''def compile_template(template):
    compiled = compile(template, '<string>', 'exec')
    exec(compiled)''',
    ],
    
    'deserialization': [
        # CWE-502: Deserialization of Untrusted Data
        '''def load_session(session_data):
    import pickle
    return pickle.loads(session_data)''',
        
        '''def restore_object(data):
    import pickle
    obj = pickle.loads(base64.b64decode(data))
    return obj''',
        
        '''def load_config(config_bytes):
    import marshal
    return marshal.loads(config_bytes)''',
        
        '''def deserialize_user(data):
    import pickle
    user = pickle.loads(data)
    return user''',
    ],
    
    'xxe': [
        # CWE-611: XML External Entity
        '''def parse_xml(xml_data):
    from lxml import etree
    doc = etree.parse(xml_data)
    return doc''',
        
        '''def load_xml_config(xml_string):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_string)
    return root''',
        
        '''def process_xml(xml_file):
    from xml.dom import minidom
    doc = minidom.parse(xml_file)
    return doc''',
        
        '''def read_xml_data(xml_content):
    import xml.sax
    parser = xml.sax.make_parser()
    parser.parse(xml_content)''',
    ],
    
    'hardcoded_secrets': [
        # CWE-798: Use of Hard-coded Credentials
        '''def connect_to_db():
    password = "admin123"
    conn = psycopg2.connect(host="localhost", password=password)
    return conn''',
        
        '''def authenticate():
    API_KEY = "sk-1234567890abcdef"
    return requests.get(url, headers={"Authorization": f"Bearer {API_KEY}"})''',
        
        '''def encrypt_data(data):
    key = "my_secret_key_12345"
    cipher = AES.new(key.encode(), AES.MODE_EAX)
    return cipher.encrypt(data)''',
        
        '''def send_email():
    smtp_password = "P@ssw0rd123"
    server.login("admin@example.com", smtp_password)''',
    ],
}


# Safe code patterns (patched versions)
SAFE_PATTERNS = [
    # SQL Injection - Fixed
    '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id=?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()''',
    
    '''def login(username, password):
    sql = "SELECT * FROM users WHERE username=? AND password=?"
    return db.execute(sql, (username, password)).fetchone()''',
    
    # Command Injection - Fixed
    '''def backup_file(filename):
    safe_filename = os.path.basename(filename)
    subprocess.run(["tar", "-czf", "backup.tar.gz", safe_filename])''',
    
    '''def ping_host(hostname):
    import ipaddress
    ipaddress.ip_address(hostname)  # Validate
    result = subprocess.run(["ping", "-c", "4", hostname], capture_output=True)
    return result.stdout''',
    
    # XSS - Fixed
    '''def display_comment(comment):
    import html
    safe_comment = html.escape(comment)
    return f"<div class='comment'>{safe_comment}</div>"''',
    
    '''def render_user_profile(name, bio):
    from markupsafe import escape
    return f"<h1>{escape(name)}</h1><p>{escape(bio)}</p>"''',
    
    # Path Traversal - Fixed
    '''def read_file(filename):
    safe_name = os.path.basename(filename)
    safe_path = os.path.join("uploads", safe_name)
    if not os.path.abspath(safe_path).startswith(os.path.abspath("uploads")):
        raise ValueError("Invalid path")
    with open(safe_path, 'r') as f:
        return f.read()''',
    
    '''def load_template(template_name):
    allowed_templates = ['index.html', 'about.html', 'contact.html']
    if template_name not in allowed_templates:
        raise ValueError("Invalid template")
    return open(f"templates/{template_name}").read()''',
    
    # Code Injection - Fixed
    '''def execute_formula(formula):
    import ast
    allowed_ops = {ast.Add, ast.Sub, ast.Mult, ast.Div}
    tree = ast.parse(formula, mode='eval')
    for node in ast.walk(tree):
        if isinstance(node, ast.operator) and type(node) not in allowed_ops:
            raise ValueError("Invalid operation")
    result = ast.literal_eval(formula)
    return result''',
    
    # Deserialization - Fixed
    '''def load_session(session_data):
    import json
    return json.loads(session_data)''',
    
    '''def restore_object(data):
    import json
    obj = json.loads(base64.b64decode(data))
    return obj''',
    
    # XXE - Fixed
    '''def parse_xml(xml_data):
    from defusedxml import ElementTree
    doc = ElementTree.parse(xml_data)
    return doc''',
    
    '''def load_xml_config(xml_string):
    from defusedxml.ElementTree import fromstring
    root = fromstring(xml_string)
    return root''',
    
    # Hardcoded Secrets - Fixed
    '''def connect_to_db():
    import os
    password = os.environ.get('DB_PASSWORD')
    conn = psycopg2.connect(host="localhost", password=password)
    return conn''',
    
    '''def authenticate():
    import os
    API_KEY = os.environ.get('API_KEY')
    return requests.get(url, headers={"Authorization": f"Bearer {API_KEY}"})''',
]


def generate_cve_like_dataset(n_samples: int = 5000, output_path: str = 'data/cve_like_training.csv') -> pd.DataFrame:
    """
    Generate a realistic CVE-like training dataset.
    
    Args:
        n_samples: Number of samples to generate
        output_path: Where to save the CSV file
        
    Returns:
        DataFrame with training data
    """
    training_data = []
    
    # Calculate samples per vulnerability type
    vuln_types = list(REAL_CVE_PATTERNS.keys())
    vulnerable_per_type = n_samples // (2 * len(vuln_types))
    
    # CWE to urgency mapping (based on real CVSS scores)
    cwe_urgency = {
        'sql_injection': (95.0, 'CWE-89'),
        'command_injection': (95.0, 'CWE-78'),
        'code_injection': (95.0, 'CWE-94'),
        'xss': (85.0, 'CWE-79'),
        'path_traversal': (80.0, 'CWE-22'),
        'deserialization': (80.0, 'CWE-502'),
        'xxe': (75.0, 'CWE-611'),
        'hardcoded_secrets': (90.0, 'CWE-798'),
    }
    
    print(f"Generating {n_samples} CVE-like samples...")
    print(f"  Vulnerable samples: {n_samples // 2}")
    print(f"  Safe samples: {n_samples // 2}")
    
    # Generate vulnerable samples
    for vuln_type in vuln_types:
        patterns = REAL_CVE_PATTERNS[vuln_type]
        urgency, cwe = cwe_urgency[vuln_type]
        
        for _ in range(vulnerable_per_type):
            code = random.choice(patterns)
            
            # Add some variation in urgency
            urgency_var = urgency + random.uniform(-5, 5)
            urgency_var = max(50, min(100, urgency_var))
            
            training_data.append({
                'code': code,
                'is_vulnerable': 1,
                'urgency_score': urgency_var,
                'cwe': cwe,
                'vulnerability_type': vuln_type,
                'source': 'cve_like'
            })
    
    # Generate safe samples
    safe_needed = n_samples // 2
    for _ in range(safe_needed):
        code = random.choice(SAFE_PATTERNS)
        
        training_data.append({
            'code': code,
            'is_vulnerable': 0,
            'urgency_score': random.uniform(10, 25),
            'cwe': '',
            'vulnerability_type': 'safe',
            'source': 'cve_like'
        })
    
    # Create DataFrame
    df = pd.DataFrame(training_data)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    if output_path:
        df.to_csv(output_path, index=False)
        print(f"\n✓ Dataset saved to: {output_path}")
        print(f"\nDataset statistics:")
        print(f"  Total samples: {len(df)}")
        print(f"  Vulnerable: {df['is_vulnerable'].sum()} ({df['is_vulnerable'].sum()/len(df)*100:.1f}%)")
        print(f"  Safe: {(df['is_vulnerable']==0).sum()} ({(df['is_vulnerable']==0).sum()/len(df)*100:.1f}%)")
        print(f"\n  Vulnerability type distribution:")
        for vtype in df[df['is_vulnerable']==1]['vulnerability_type'].value_counts().items():
            print(f"    {vtype[0]}: {vtype[1]}")
    
    return df


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate CVE-like training dataset')
    parser.add_argument('--samples', type=int, default=5000, help='Number of samples to generate')
    parser.add_argument('--output', type=str, default='data/cve_like_training.csv', help='Output path')
    
    args = parser.parse_args()
    
    print("="*60)
    print("CVE-like Dataset Generator")
    print("="*60)
    print()
    
    generate_cve_like_dataset(n_samples=args.samples, output_path=args.output)
    
    print("\nNext step: Train your model with:")
    print(f"  python train.py --data {args.output} --urgency-model ridge")
