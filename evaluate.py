"""
Model evaluation script.

Evaluates trained models on test dataset and displays metrics.
"""

import argparse
import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split

from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor, evaluate_classifier, evaluate_regressor
from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.utils import print_metrics


def load_models(model_dir: str):
    """Load trained models from disk."""
    classifier_path = os.path.join(model_dir, 'vulnerability_classifier.pkl')
    predictor_path = os.path.join(model_dir, 'urgency_predictor.pkl')
    extractor_path = os.path.join(model_dir, 'feature_extractor.pkl')
    
    if not all(os.path.exists(p) for p in [classifier_path, predictor_path, extractor_path]):
        print("Error: Models not found. Please run train.py first.")
        sys.exit(1)
    
    print("Loading models...")
    classifier = VulnerabilityClassifier.load(classifier_path)
    predictor = UrgencyPredictor.load(predictor_path)
    extractor = joblib.load(extractor_path)
    
    return classifier, predictor, extractor


def main():
    parser = argparse.ArgumentParser(description='Evaluate trained models')
    parser.add_argument('--data', type=str, default='data/training_dataset.csv',
                       help='Path to dataset CSV')
    parser.add_argument('--model-dir', type=str, default='models',
                       help='Directory containing trained models')
    parser.add_argument('--test-size', type=float, default=0.2,
                       help='Proportion of data for testing')
    parser.add_argument('--random-seed', type=int, default=42,
                       help='Random seed for reproducibility')
    parser.add_argument('--verbose', action='store_true',
                       help='Show detailed evaluation')
    
    args = parser.parse_args()
    
    # Load models
    classifier, predictor, extractor = load_models(args.model_dir)
    
    # Load dataset
    print(f"\nLoading dataset from {args.data}...")
    df = pd.read_csv(args.data)
    print(f"Loaded {len(df)} samples")
    
    # Extract features
    print("\nExtracting features...")
    X = extractor.transform(df['code'].tolist())
    y_vulnerable = df['is_vulnerable'].values
    y_urgency = df['urgency_score'].values
    
    # Split data (same way as training)
    _, X_test, _, y_vuln_test, _, y_urg_test = train_test_split(
        X, y_vulnerable, y_urgency,
        test_size=args.test_size,
        random_state=args.random_seed,
        stratify=y_vulnerable
    )
    
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Evaluate classifier
    print("\n" + "="*60)
    print("VULNERABILITY CLASSIFIER EVALUATION")
    print("="*60)
    
    classifier_metrics = evaluate_classifier(classifier, X_test, y_vuln_test)
    print_metrics(classifier_metrics, "Classification Metrics")
    
    if args.verbose:
        # Confusion matrix
        from sklearn.metrics import confusion_matrix
        y_pred = classifier.predict(X_test)
        cm = confusion_matrix(y_vuln_test, y_pred)
        
        print("\nConfusion Matrix:")
        print("                 Predicted")
        print("                 Safe  Vulnerable")
        print(f"Actual Safe      {cm[0,0]:4d}  {cm[0,1]:4d}")
        print(f"       Vulnerable {cm[1,0]:4d}  {cm[1,1]:4d}")
        
        # Classification report
        from sklearn.metrics import classification_report
        print("\nClassification Report:")
        print(classification_report(y_vuln_test, y_pred, target_names=['Safe', 'Vulnerable']))
    
    # Evaluate predictor
    print("\n" + "="*60)
    print("URGENCY PREDICTOR EVALUATION")
    print("="*60)
    
    predictor_metrics = evaluate_regressor(predictor, X_test, y_urg_test)
    print_metrics(predictor_metrics, "Regression Metrics")
    
    if args.verbose:
        # Prediction distribution
        y_pred_urg = predictor.predict(X_test)
        
        print("\nPrediction Statistics:")
        print(f"  True urgency mean:      {y_urg_test.mean():.2f} ± {y_urg_test.std():.2f}")
        print(f"  Predicted urgency mean: {y_pred_urg.mean():.2f} ± {y_pred_urg.std():.2f}")
        print(f"  Min error:              {(y_pred_urg - y_urg_test).min():.2f}")
        print(f"  Max error:              {(y_pred_urg - y_urg_test).max():.2f}")
        
        # Sample predictions
        print("\nSample Predictions (first 10):")
        print(f"{'True':>8} {'Predicted':>10} {'Error':>8}")
        print("-" * 30)
        for i in range(min(10, len(y_urg_test))):
            error = y_pred_urg[i] - y_urg_test[i]
            print(f"{y_urg_test[i]:8.2f} {y_pred_urg[i]:10.2f} {error:8.2f}")
    
    # Overall performance summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"\nVulnerability Detection:")
    print(f"  Accuracy:  {classifier_metrics['accuracy']*100:.2f}%")
    print(f"  Precision: {classifier_metrics['precision']*100:.2f}%")
    print(f"  Recall:    {classifier_metrics['recall']*100:.2f}%")
    print(f"  F1-Score:  {classifier_metrics['f1_score']*100:.2f}%")
    
    print(f"\nUrgency Prediction:")
    print(f"  R² Score:  {predictor_metrics['r2_score']:.4f}")
    print(f"  MAE:       {predictor_metrics['mae']:.2f} points")
    print(f"  RMSE:      {predictor_metrics['rmse']:.2f} points")
    
    print("\n" + "="*60)


if __name__ == '__main__':
    main()
