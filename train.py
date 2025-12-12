"""
Training pipeline for vulnerability classifier and urgency predictor.

Trains both models on the dataset and saves them to disk.
"""

import argparse
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor, evaluate_classifier, evaluate_regressor
from vulnerapred.utils import ensure_dir, print_metrics, save_metrics


def load_dataset(csv_path: str):
    """Load dataset from CSV file."""
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} samples")
    print(f"  Vulnerable: {df['is_vulnerable'].sum()} ({df['is_vulnerable'].mean()*100:.1f}%)")
    print(f"  Urgency range: {df['urgency_score'].min():.1f} - {df['urgency_score'].max():.1f}")
    return df


def main():
    parser = argparse.ArgumentParser(description='Train vulnerability detection and urgency prediction models')
    parser.add_argument('--data', type=str, default='data/training_dataset.csv', 
                       help='Path to training dataset CSV')
    parser.add_argument('--output-dir', type=str, default='models', 
                       help='Directory to save trained models')
    parser.add_argument('--test-size', type=float, default=0.2, 
                       help='Proportion of data for testing')
    parser.add_argument('--urgency-model', type=str, default='linear', 
                       choices=['linear', 'ridge', 'lasso'],
                       help='Type of regression model for urgency prediction')
    parser.add_argument('--use-polynomial', action='store_true',
                       help='Use polynomial features for regression')
    parser.add_argument('--poly-degree', type=int, default=2,
                       help='Degree of polynomial features')
    parser.add_argument('--max-features', type=int, default=100,
                       help='Maximum TF-IDF features to extract')
    parser.add_argument('--random-seed', type=int, default=42,
                       help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    ensure_dir(args.output_dir)
    
    # Load dataset
    df = load_dataset(args.data)
    
    # Extract features
    print("\nExtracting features...")
    extractor = CodeFeatureExtractor(max_features=args.max_features, use_tfidf=True)
    X = extractor.fit_transform(df['code'].tolist())
    y_vulnerable = df['is_vulnerable'].values
    y_urgency = df['urgency_score'].values
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"Number of features: {X.shape[1]}")
    
    # Split data
    print(f"\nSplitting data (test size: {args.test_size})...")
    X_train, X_test, y_vuln_train, y_vuln_test, y_urg_train, y_urg_test = train_test_split(
        X, y_vulnerable, y_urgency, 
        test_size=args.test_size, 
        random_state=args.random_seed,
        stratify=y_vulnerable
    )
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Train vulnerability classifier
    print("\n" + "="*60)
    print("Training Vulnerability Classifier (Logistic Regression)")
    print("="*60)
    
    # Add class weight balancing for better learning
    classifier = VulnerabilityClassifier(
        random_state=args.random_seed,
        max_iter=2000,  # Ensure convergence
        class_weight='balanced'  # Handle class imbalance
    )
    classifier.train(X_train, y_vuln_train)
    
    # Evaluate classifier
    train_metrics = evaluate_classifier(classifier, X_train, y_vuln_train)
    test_metrics = evaluate_classifier(classifier, X_test, y_vuln_test)
    
    print_metrics(train_metrics, "Classifier Training Metrics")
    print_metrics(test_metrics, "Classifier Test Metrics")
    
    # Save classifier
    classifier_path = os.path.join(args.output_dir, 'vulnerability_classifier.pkl')
    classifier.save(classifier_path)
    print(f"✓ Classifier saved to: {classifier_path}")
    
    # Save classifier metrics
    metrics_path = os.path.join(args.output_dir, 'classifier_metrics.json')
    save_metrics({'train': train_metrics, 'test': test_metrics}, metrics_path)
    
    # Train urgency predictor
    print("\n" + "="*60)
    model_name = f"{args.urgency_model.capitalize()} Regression"
    if args.use_polynomial:
        model_name += f" with Polynomial Features (degree={args.poly_degree})"
    print(f"Training Urgency Predictor ({model_name})")
    print("="*60)
    
    predictor = UrgencyPredictor(
        model_type=args.urgency_model,
        use_polynomial=args.use_polynomial,
        poly_degree=args.poly_degree,
        random_state=args.random_seed
    )
    predictor.train(X_train, y_urg_train)
    
    # Evaluate predictor
    train_metrics = evaluate_regressor(predictor, X_train, y_urg_train)
    test_metrics = evaluate_regressor(predictor, X_test, y_urg_test)
    
    print_metrics(train_metrics, "Predictor Training Metrics")
    print_metrics(test_metrics, "Predictor Test Metrics")
    
    # Save predictor
    predictor_path = os.path.join(args.output_dir, 'urgency_predictor.pkl')
    predictor.save(predictor_path)
    print(f"✓ Predictor saved to: {predictor_path}")
    
    # Save predictor metrics
    metrics_path = os.path.join(args.output_dir, 'predictor_metrics.json')
    save_metrics({'train': train_metrics, 'test': test_metrics}, metrics_path)
    
    # Save feature extractor
    extractor_path = os.path.join(args.output_dir, 'feature_extractor.pkl')
    import joblib
    joblib.dump(extractor, extractor_path)
    print(f"✓ Feature extractor saved to: {extractor_path}")
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
    print(f"\nAll models saved to: {args.output_dir}/")
    print("  - vulnerability_classifier.pkl")
    print("  - urgency_predictor.pkl")
    print("  - feature_extractor.pkl")
    print("\nUse predict.py to make predictions on new code snippets.")


if __name__ == '__main__':
    main()
