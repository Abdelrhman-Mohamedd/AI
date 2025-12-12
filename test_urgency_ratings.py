"""
Test script to verify critical vulnerabilities are properly rated.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from predict import load_models, predict_code

print("=" * 80)
print("CRITICAL VULNERABILITY PRIORITY TEST")
print("=" * 80)

# Load models
classifier, predictor, extractor = load_models('models')

# Test cases: (code, expected_min_urgency, expected_priority)
test_cases = [
    ("eval(user_input)", 80, "CRITICAL"),
    ("exec(malicious_code)", 80, "CRITICAL"),
    ("os.system(command)", 80, "CRITICAL"),
    ("subprocess.run(cmd, shell=True)", 80, "CRITICAL"),
    ("cursor.execute('SELECT * FROM users WHERE id=' + user_id)", 80, "CRITICAL"),
    ("cursor.execute(f'DELETE FROM data WHERE id={uid}')", 80, "CRITICAL"),
    ("import pickle; pickle.loads(data)", 80, "CRITICAL"),
    ("yaml.load(user_data)", 60, "HIGH"),
    ("hashlib.md5(password)", 40, "MEDIUM"),
    ("password = 'hardcoded123'", 60, "HIGH"),
    ("x = 1 + 1", 0, "MINIMAL/LOW"),  # Safe code
]

print("\nTesting vulnerability ratings...\n")

passed = 0
failed = 0

for code, min_urgency, expected_priority in test_cases:
    is_vuln, vuln_score, urgency = predict_code(code, classifier, predictor, extractor)
    
    # Determine priority
    if urgency >= 80:
        priority = "CRITICAL"
    elif urgency >= 60:
        priority = "HIGH"
    elif urgency >= 40:
        priority = "MEDIUM"
    elif urgency >= 20:
        priority = "LOW"
    else:
        priority = "MINIMAL"
    
    # Check if it meets expectations
    passed_test = urgency >= min_urgency or not is_vuln
    
    status = "✓ PASS" if passed_test else "✗ FAIL"
    
    if passed_test:
        passed += 1
    else:
        failed += 1
    
    print(f"{status} | Urgency: {urgency:5.1f} | Priority: {priority:8s} | Expected: {expected_priority:15s}")
    print(f"     Code: {code[:60]}")
    print()

print("=" * 80)
print(f"RESULTS: {passed} passed, {failed} failed")
print("=" * 80)

if failed == 0:
    print("\n✓ All tests passed! Critical vulnerabilities are properly prioritized.")
    sys.exit(0)
else:
    print(f"\n✗ {failed} test(s) failed. Some vulnerabilities may not be properly rated.")
    sys.exit(1)
