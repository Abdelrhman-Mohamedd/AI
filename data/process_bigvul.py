"""
Process Big-Vul dataset for training on real CVE data.

This script processes the Big-Vul dataset which contains real vulnerable
code from GitHub repositories. It filters Python code and maps it to the
format expected by our training pipeline.

Usage:
    python data/process_bigvul.py --input MSR_data_cleaned.csv --output data/bigvul_training.csv
"""

import pandas as pd
import argparse
from pathlib import Path


def calculate_urgency_from_cwe(cwe: str) -> float:
    """
    Calculate urgency score from CWE ID.
    
    Args:
        cwe: CWE identifier string (e.g., "CWE-89", "CWE-78")
        
    Returns:
        Urgency score between 0-100
    """
    # Critical vulnerabilities (score: 90-100)
    critical_cwes = {
        '89': 95.0,   # SQL injection
        '78': 95.0,   # Command injection
        '94': 95.0,   # Code injection
        '798': 90.0,  # Hardcoded credentials
    }
    
    # High severity vulnerabilities (score: 70-89)
    high_cwes = {
        '79': 85.0,   # XSS
        '22': 80.0,   # Path traversal
        '502': 80.0,  # Deserialization
        '611': 75.0,  # XXE
        '434': 75.0,  # Unrestricted file upload
        '352': 70.0,  # CSRF
    }
    
    # Medium severity vulnerabilities (score: 50-69)
    medium_cwes = {
        '200': 60.0,  # Information disclosure
        '601': 55.0,  # Open redirect
        '862': 55.0,  # Missing authorization
        '863': 55.0,  # Incorrect authorization
    }
    
    cwe_str = str(cwe).upper()
    
    # Check critical
    for cwe_id, score in critical_cwes.items():
        if f'CWE-{cwe_id}' in cwe_str or cwe_id in cwe_str:
            return score
    
    # Check high
    for cwe_id, score in high_cwes.items():
        if f'CWE-{cwe_id}' in cwe_str or cwe_id in cwe_str:
            return score
    
    # Check medium
    for cwe_id, score in medium_cwes.items():
        if f'CWE-{cwe_id}' in cwe_str or cwe_id in cwe_str:
            return score
    
    # Default for unknown vulnerabilities
    return 50.0


def process_bigvul_dataset(
    input_path: str,
    output_path: str,
    max_samples: int = None,
    min_code_length: int = 10,
    max_code_length: int = 5000
) -> None:
    """
    Process Big-Vul CSV dataset for training.
    
    Args:
        input_path: Path to Big-Vul CSV file (MSR_data_cleaned.csv)
        output_path: Output path for processed dataset
        max_samples: Maximum samples to use (None = use all)
        min_code_length: Minimum code length in characters
        max_code_length: Maximum code length in characters
    """
    print(f"Loading Big-Vul dataset from {input_path}...")
    
    try:
        df = pd.read_csv(input_path)
    except FileNotFoundError:
        print(f"Error: File not found: {input_path}")
        print("\nTo download Big-Vul dataset, run:")
        print("  wget https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset/raw/master/MSR_data_cleaned.csv")
        return
    
    print(f"Loaded {len(df)} total samples")
    
    # Filter for Python code
    if 'lang' in df.columns:
        df_python = df[df['lang'] == 'Python'].copy()
        print(f"Found {len(df_python)} Python samples")
    else:
        print("Warning: 'lang' column not found, using all samples")
        df_python = df.copy()
    
    # Filter by code length
    if 'func' in df_python.columns:
        df_python['code_length'] = df_python['func'].str.len()
        df_python = df_python[
            (df_python['code_length'] >= min_code_length) & 
            (df_python['code_length'] <= max_code_length)
        ]
        print(f"After filtering by code length: {len(df_python)} samples")
    
    # Limit samples if specified
    if max_samples and len(df_python) > max_samples:
        df_python = df_python.sample(n=max_samples, random_state=42)
        print(f"Randomly sampled {max_samples} samples")
    
    # Create training format
    training_data = []
    
    print("\nProcessing vulnerable samples...")
    df_vulnerable = df_python[df_python.get('target', 0) == 1]
    
    for idx, row in df_vulnerable.iterrows():
        code = row.get('func', '')
        
        if not code or len(code.strip()) < min_code_length:
            continue
        
        # Calculate urgency from CWE
        cwe = str(row.get('cwe', ''))
        urgency = calculate_urgency_from_cwe(cwe)
        
        training_data.append({
            'code': code,
            'is_vulnerable': 1,
            'urgency_score': urgency,
            'cwe': cwe,
            'source': 'bigvul',
            'commit': row.get('commit_id', ''),
            'project': row.get('project', '')
        })
    
    print(f"Processed {len(training_data)} vulnerable samples")
    
    # Balance with safe samples
    print("\nProcessing safe samples...")
    df_safe = df_python[df_python.get('target', 0) == 0]
    
    # Use same number of safe samples as vulnerable (balanced dataset)
    num_safe_needed = len(training_data)
    
    if len(df_safe) > num_safe_needed:
        df_safe = df_safe.sample(n=num_safe_needed, random_state=42)
    
    for idx, row in df_safe.iterrows():
        code = row.get('func', '')
        
        if not code or len(code.strip()) < min_code_length:
            continue
        
        training_data.append({
            'code': code,
            'is_vulnerable': 0,
            'urgency_score': 15.0,
            'cwe': '',
            'source': 'bigvul',
            'commit': row.get('commit_id', ''),
            'project': row.get('project', '')
        })
    
    print(f"Processed {len(training_data) - len(df_vulnerable)} safe samples")
    
    # Create DataFrame and save
    result_df = pd.DataFrame(training_data)
    
    # Shuffle
    result_df = result_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Create output directory if needed
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save
    result_df.to_csv(output_path, index=False)
    
    print(f"\n{'='*60}")
    print(f"✓ Successfully created training dataset!")
    print(f"{'='*60}")
    print(f"Total samples: {len(result_df)}")
    print(f"  Vulnerable: {result_df['is_vulnerable'].sum()} ({result_df['is_vulnerable'].sum()/len(result_df)*100:.1f}%)")
    print(f"  Safe: {(result_df['is_vulnerable'] == 0).sum()} ({(result_df['is_vulnerable'] == 0).sum()/len(result_df)*100:.1f}%)")
    print(f"\nUrgency score distribution:")
    print(f"  Mean: {result_df['urgency_score'].mean():.1f}")
    print(f"  Median: {result_df['urgency_score'].median():.1f}")
    print(f"  Min: {result_df['urgency_score'].min():.1f}")
    print(f"  Max: {result_df['urgency_score'].max():.1f}")
    print(f"\nSaved to: {output_path}")
    print(f"\nNext step: Train your model with:")
    print(f"  python train.py --data {output_path} --urgency-model ridge")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Process Big-Vul dataset for vulnerability prediction training'
    )
    parser.add_argument(
        '--input',
        type=str,
        default='MSR_data_cleaned.csv',
        help='Path to Big-Vul CSV file (default: MSR_data_cleaned.csv)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/bigvul_training.csv',
        help='Output path for processed dataset (default: data/bigvul_training.csv)'
    )
    parser.add_argument(
        '--max-samples',
        type=int,
        default=None,
        help='Maximum samples to use (default: use all available)'
    )
    parser.add_argument(
        '--min-code-length',
        type=int,
        default=10,
        help='Minimum code length in characters (default: 10)'
    )
    parser.add_argument(
        '--max-code-length',
        type=int,
        default=5000,
        help='Maximum code length in characters (default: 5000)'
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("Big-Vul Dataset Processor")
    print("="*60)
    print()
    
    process_bigvul_dataset(
        input_path=args.input,
        output_path=args.output,
        max_samples=args.max_samples,
        min_code_length=args.min_code_length,
        max_code_length=args.max_code_length
    )


if __name__ == '__main__':
    main()
