"""
Enhanced vulnerability dataset generator with realistic patterns.

Generates labeled code snippets with vulnerability labels and urgency scores.
"""

import random
import pandas as pd
import os


# Real vulnerable code patterns
VULNERABLE_TEMPLATES = [
    # Command injection - CRITICAL
    "os.system(user_input)",
    "os.system(cmd)",
    "os.system(f'rm -rf {user_path}')",
    "subprocess.call(cmd, shell=True)",
    "subprocess.call(user_input, shell=True)",
    "subprocess.Popen(user_cmd, shell=True)",
    "subprocess.run(command, shell=True)",
    "os.popen(command).read()",
    "commands.getoutput(user_data)",
    
    # Code execution - CRITICAL
    "eval(user_input)",
    "eval(request.GET['code'])",
    "exec(user_code)",
    "exec(compiled_code)",
    "compile(user_string, '<string>', 'exec')",
    "exec(open(filename).read())",
    "exec(open(config_file).read())",
    "__import__(user_module)",
    "__import__(module_name)",
    
    # SQL injection - HIGH
    "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
    "cursor.execute('SELECT * FROM users WHERE name=' + name)",
    "cursor.execute(f'DELETE FROM {table} WHERE name={name}')",
    "db.query('INSERT INTO logs VALUES(' + data + ')')",
    "db.execute('INSERT INTO table VALUES(' + values + ')')",
    "conn.execute('UPDATE users SET pass=' + pwd)",
    "query = 'SELECT * FROM data WHERE user=' + username",
    "sql = f'DROP TABLE {table_name}'",
    "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
    "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
    "cursor.execute(f\"INSERT INTO logs (msg) VALUES ('{message}')\")",
    "query = f'SELECT * FROM products WHERE name = {product_name}'",
    "cursor.execute('SELECT * FROM table WHERE col=' + str(value))",
    "db.query(f'UPDATE users SET email={email} WHERE id={uid}')",
    "sql = \"SELECT * FROM data WHERE name='\" + user_name + \"'\"",
    "cursor.execute(\"DELETE FROM users WHERE username='\" + username + \"')\")",
    "query = 'SELECT * FROM {} WHERE id={}'.format(table, id)",
    "cursor.execute('SELECT * FROM users WHERE name=%s' % username)",
    
    # Path traversal - HIGH
    "open('../../../etc/passwd')",
    "open('../../config/secrets.txt')",
    "open(user_path)",
    "open(filename)",
    "open(os.path.join(base, user_file))",
    "with open(user_filename, 'r') as f: return f.read()",
    "file = open(request.GET['file'])",
    
    # Deserialization - CRITICAL
    "pickle.loads(user_data)",
    "pickle.loads(untrusted_data)",
    "pickle.load(open(file, 'rb'))",
    "pickle.load(user_file)",
    "yaml.load(user_yaml)",
    "yaml.load(data)",
    "marshal.loads(data)",
    "marshal.loads(input_data)",
    
    # XXE/XML - HIGH
    "etree.parse(xml_file)",
    "etree.parse(user_xml)",
    "etree.fromstring(user_xml)",
    "etree.fromstring(xml_data)",
    "xml.dom.minidom.parseString(data)",
    "xml.etree.ElementTree.parse(file)",
    
    # File operations without validation - MEDIUM
    "shutil.rmtree(user_directory)",
    "shutil.rmtree(path)",
    "os.remove(user_file)",
    "os.remove(filename)",
    "os.unlink(path)",
    "os.unlink(user_path)",
    
    # Hardcoded secrets - MEDIUM
    "API_KEY = 'sk-1234567890abcdef'",
    "password = 'admin123'",
    "SECRET_KEY = 'my-secret-key-123'",
    "db_password = 'P@ssw0rd'",
    
    # Dangerous imports - HIGH
    "from subprocess import *",
    "import pickle; pickle.loads(data)",
    "from os import system",
]

# Safe code patterns
SAFE_TEMPLATES = [
    # Normal operations
    "x = a + b",
    "result = calculate_sum(numbers)",
    "def hello(): return 'world'",
    "if x > 0: print(x)",
    "for i in range(10): process(i)",
    "while count < 10: count += 1",
    "try: process() except: pass",
    
    # Safe string operations
    "name = input().strip()",
    "text = text.lower()",
    "words = sentence.split()",
    "cleaned = text.replace('old', 'new')",
    "result = ' '.join(words)",
    
    # Safe math
    "import math; math.sqrt(16)",
    "total = sum(values)",
    "average = total / count",
    "maximum = max(numbers)",
    "import numpy as np; np.mean(data)",
    
    # Safe list operations
    "items.append(new_item)",
    "filtered = [x for x in items if x > 0]",
    "sorted_list = sorted(data)",
    "reversed_list = list(reversed(items))",
    "combined = list1 + list2",
    
    # Safe dict operations
    "config = {'key': 'value'}",
    "value = settings.get('name', 'default')",
    "data = {k: v for k, v in items}",
    "keys = list(dictionary.keys())",
    
    # Safe file operations (with literal paths)
    "with open('config.json', 'r') as f: data = json.load(f)",
    "with open('data.txt', 'w') as f: f.write(text)",
    "df = pd.read_csv('data.csv')",
    "import json; json.load(open('settings.json'))",
    
    # Safe database (parameterized)
    "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    "cursor.execute('INSERT INTO logs VALUES (?, ?)', (msg, time))",
    "db.query(User).filter_by(id=user_id).first()",
    "session.query(Model).filter(Model.id == id).all()",
    
    # Safe functions
    "def add(a, b): return a + b",
    "def multiply(x, y): return x * y",
    "class Calculator: pass",
    "logger.info('Processing complete')",
    "print(f'Result: {result}')",
    
    # Safe imports
    "import json",
    "from datetime import datetime",
    "import pandas as pd",
    "import numpy as np",
    "from collections import defaultdict",
]

# Urgency factors for vulnerable code
URGENCY_FACTORS = {
    'eval': 95, 'exec': 95, 'os.system': 90, 'pickle.loads': 85,
    'subprocess': 80, 'shell=True': 85, 'SELECT': 70, 'DELETE': 75,
    'INSERT': 65, 'open(': 60, 'etree': 70, 'yaml.load': 75,
    'user_': 20, 'input': 15, 'request': 25, 'command': 30,
    'filename': 25, 'path': 20, 'file': 15, 'data': 10
}


def generate_code_snippet(is_vulnerable: bool) -> str:
    """
    Generate a single code snippet.
    
    Args:
        is_vulnerable: Whether to generate vulnerable or safe code
        
    Returns:
        Code snippet as string
    """
    templates = VULNERABLE_TEMPLATES if is_vulnerable else SAFE_TEMPLATES
    snippet = random.choice(templates)
    
    # Sometimes add realistic context
    if random.random() < 0.4:
        if is_vulnerable:
            contexts = [
                f"def handle_request(user_input):\n    {snippet}",
                f"def process_data(data):\n    {snippet}\n    return result",
                f"# API endpoint\n{snippet}",
                f"# User input handler\ntry:\n    {snippet}\nexcept: pass",
            ]
        else:
            contexts = [
                f"def calculate():\n    {snippet}\n    return result",
                f"# Helper function\n{snippet}",
                f"def main():\n    {snippet}",
                snippet,
            ]
        snippet = random.choice(contexts)
    
    return snippet


def calculate_urgency_score(code: str, is_vulnerable: bool) -> float:
    """
    Calculate urgency score based on code characteristics.
    
    Args:
        code: Code snippet
        is_vulnerable: Whether code is vulnerable
        
    Returns:
        Urgency score (0-100)
    """
    if not is_vulnerable:
        # Safe code has low urgency
        return random.uniform(5, 35)
    
    # Base score for vulnerable code
    base_score = 50
    
    # Add urgency based on dangerous patterns
    code_lower = code.lower()
    for pattern, weight in URGENCY_FACTORS.items():
        if pattern in code_lower:
            base_score += weight * 0.3
    
    # Critical patterns get extra weight
    critical_patterns = ['eval', 'exec', 'pickle.loads', 'os.system', 'shell=True']
    for pattern in critical_patterns:
        if pattern in code:
            base_score += random.uniform(15, 25)
    
    # User input makes it more critical
    user_indicators = ['user_', 'request', 'input()', 'GET', 'POST', 'argv']
    if any(indicator in code for indicator in user_indicators):
        base_score += random.uniform(10, 20)
    
    # Add some randomness
    base_score += random.uniform(-5, 10)
    
    # Cap at 100
    return min(100, max(40, base_score))


def generate_dataset(n_samples: int = 1000, vulnerable_ratio: float = 0.5, output_path: str = None) -> pd.DataFrame:
    """
    Generate synthetic dataset for training.
    
    Args:
        n_samples: Number of samples to generate
        vulnerable_ratio: Proportion of vulnerable samples (0-1)
        output_path: Path to save CSV file (optional)
        
    Returns:
        DataFrame with columns: code, is_vulnerable, urgency_score
    """
    data = []
    
    n_vulnerable = int(n_samples * vulnerable_ratio)
    n_safe = n_samples - n_vulnerable
    
    print(f"Generating {n_samples} code snippets...")
    print(f"  - Vulnerable: {n_vulnerable}")
    print(f"  - Safe: {n_safe}")
    
    # Generate vulnerable samples
    for i in range(n_vulnerable):
        code = generate_code_snippet(is_vulnerable=True)
        urgency = calculate_urgency_score(code, is_vulnerable=True)
        data.append({
            'code': code,
            'is_vulnerable': 1,
            'urgency_score': urgency
        })
        
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{n_vulnerable} vulnerable samples...")
    
    # Generate safe samples
    for i in range(n_safe):
        code = generate_code_snippet(is_vulnerable=False)
        urgency = calculate_urgency_score(code, is_vulnerable=False)
        data.append({
            'code': code,
            'is_vulnerable': 0,
            'urgency_score': urgency
        })
        
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{n_safe} safe samples...")
    
    # Shuffle data
    random.shuffle(data)
    
    df = pd.DataFrame(data)
    
    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\nDataset saved to: {output_path}")
        print(f"Shape: {df.shape}")
        print(f"\nSample statistics:")
        print(f"  Vulnerable: {df['is_vulnerable'].sum()} ({df['is_vulnerable'].mean()*100:.1f}%)")
        print(f"  Urgency score range: {df['urgency_score'].min():.1f} - {df['urgency_score'].max():.1f}")
        print(f"  Urgency score mean: {df['urgency_score'].mean():.1f}")
    
    return df


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate synthetic vulnerability dataset')
    parser.add_argument('--samples', type=int, default=1000, help='Number of samples to generate')
    parser.add_argument('--vulnerable-ratio', type=float, default=0.5, help='Ratio of vulnerable samples')
    parser.add_argument('--output', type=str, default='data/training_dataset.csv', help='Output CSV path')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    generate_dataset(
        n_samples=args.samples,
        vulnerable_ratio=args.vulnerable_ratio,
        output_path=args.output
    )
