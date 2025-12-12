


"""
ML Model Visualization Script

Generates comprehensive performance graphs for trained models including:
- Confusion matrices
- ROC curves
- Feature importance plots
- Learning curves
- Regression performance plots
- Metric comparison charts
"""

import argparse
import os
import sys
import json
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, learning_curve
from sklearn.metrics import (
    confusion_matrix, roc_curve, auc, 
    precision_recall_curve, average_precision_score
)

from vulnerapred.models import VulnerabilityClassifier, UrgencyPredictor
from vulnerapred.features import CodeFeatureExtractor
from vulnerapred.utils import print_metrics


# Set style for better-looking plots
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10


def load_models_and_data(model_dir: str, data_path: str, test_size: float = 0.2, random_seed: int = 42):
    """Load trained models and prepare test data."""
    print("Loading models...")
    classifier_path = os.path.join(model_dir, 'vulnerability_classifier.pkl')
    predictor_path = os.path.join(model_dir, 'urgency_predictor.pkl')
    extractor_path = os.path.join(model_dir, 'feature_extractor.pkl')
    
    if not all(os.path.exists(p) for p in [classifier_path, predictor_path, extractor_path]):
        print("Error: Models not found. Please run train.py first.")
        sys.exit(1)
    
    classifier = VulnerabilityClassifier.load(classifier_path)
    predictor = UrgencyPredictor.load(predictor_path)
    extractor = joblib.load(extractor_path)
    
    print(f"Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    
    # Extract features
    print("Extracting features...")
    X = extractor.transform(df['code'].tolist())
    y_class = df['is_vulnerable'].values
    y_urgency = df['urgency_score'].values
    
    # Split data
    X_train, X_test, y_class_train, y_class_test, y_urgency_train, y_urgency_test = train_test_split(
        X, y_class, y_urgency, test_size=test_size, random_state=random_seed, stratify=y_class
    )
    
    return {
        'classifier': classifier,
        'predictor': predictor,
        'extractor': extractor,
        'X_train': X_train,
        'X_test': X_test,
        'y_class_train': y_class_train,
        'y_class_test': y_class_test,
        'y_urgency_train': y_urgency_train,
        'y_urgency_test': y_urgency_test,
        'df': df
    }


def plot_confusion_matrix(y_true, y_pred, output_dir: str):
    """Generate confusion matrix heatmap."""
    print("Generating confusion matrix...")
    cm = confusion_matrix(y_true, y_pred)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                xticklabels=['Safe', 'Vulnerable'],
                yticklabels=['Safe', 'Vulnerable'],
                ax=ax)
    ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
    ax.set_title('Vulnerability Classifier - Confusion Matrix', fontsize=14, fontweight='bold', pad=20)
    
    # Add accuracy text
    accuracy = (cm[0, 0] + cm[1, 1]) / cm.sum()
    plt.text(0.5, -0.15, f'Overall Accuracy: {accuracy:.2%}', 
             ha='center', transform=ax.transAxes, fontsize=11, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: confusion_matrix.png")


def plot_roc_curve(classifier, X_test, y_test, output_dir: str):
    """Generate ROC curve."""
    print("Generating ROC curve...")
    
    # Get probability predictions (use classifier method to include scaling)
    y_score = classifier.get_vulnerability_score(X_test)
    
    fpr, tpr, thresholds = roc_curve(y_test, y_score)
    roc_auc = auc(fpr, tpr)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    ax.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Positive Rate', fontsize=12, fontweight='bold')
    ax.set_title('ROC Curve - Vulnerability Classifier', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc="lower right", fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'roc_curve.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: roc_curve.png")


def plot_precision_recall_curve(classifier, X_test, y_test, output_dir: str):
    """Generate Precision-Recall curve."""
    print("Generating Precision-Recall curve...")
    
    # Get probability predictions (use classifier method to include scaling)
    y_score = classifier.get_vulnerability_score(X_test)
    
    precision, recall, thresholds = precision_recall_curve(y_test, y_score)
    avg_precision = average_precision_score(y_test, y_score)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision, color='blue', lw=2, label=f'PR curve (AP = {avg_precision:.3f})')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('Recall', fontsize=12, fontweight='bold')
    ax.set_ylabel('Precision', fontsize=12, fontweight='bold')
    ax.set_title('Precision-Recall Curve - Vulnerability Classifier', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc="lower left", fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'precision_recall_curve.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: precision_recall_curve.png")


def plot_feature_importance(classifier, extractor, output_dir: str, top_n: int = 20):
    """Plot feature importance for tree-based models."""
    print("Generating feature importance plot...")
    
    # Check if model has feature importance
    if not hasattr(classifier.model, 'feature_importances_'):
        print("⚠ Model does not support feature importance (not a tree-based model)")
        return
    
    importances = classifier.model.feature_importances_
    feature_names = extractor.get_feature_names()
    
    # Get top N features
    indices = np.argsort(importances)[-top_n:]
    
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(range(len(indices)), importances[indices], color='steelblue')
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels([feature_names[i] for i in indices])
    ax.set_xlabel('Feature Importance', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} Most Important Features', fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'feature_importance.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: feature_importance.png")


def plot_learning_curves(classifier, predictor, X, y_class, y_urgency, output_dir: str):
    """Generate learning curves to show model performance vs training size."""
    print("Generating learning curves (this may take a moment)...")
    
    # Classifier learning curve
    train_sizes, train_scores, test_scores = learning_curve(
        classifier.model, X, y_class, 
        cv=5, n_jobs=-1, 
        train_sizes=np.linspace(0.1, 1.0, 10),
        scoring='accuracy'
    )
    
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    test_mean = np.mean(test_scores, axis=1)
    test_std = np.std(test_scores, axis=1)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Classification learning curve
    ax1.plot(train_sizes, train_mean, 'o-', color='blue', label='Training score')
    ax1.plot(train_sizes, test_mean, 'o-', color='red', label='Cross-validation score')
    ax1.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color='blue')
    ax1.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1, color='red')
    ax1.set_xlabel('Training Set Size', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Accuracy Score', fontsize=12, fontweight='bold')
    ax1.set_title('Learning Curve - Vulnerability Classifier', fontsize=13, fontweight='bold', pad=15)
    ax1.legend(loc='lower right', fontsize=10)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim([0.5, 1.05])
    
    # Regression learning curve
    train_sizes_reg, train_scores_reg, test_scores_reg = learning_curve(
        predictor.model, X, y_urgency, 
        cv=5, n_jobs=-1, 
        train_sizes=np.linspace(0.1, 1.0, 10),
        scoring='r2'
    )
    
    train_mean_reg = np.mean(train_scores_reg, axis=1)
    train_std_reg = np.std(train_scores_reg, axis=1)
    test_mean_reg = np.mean(test_scores_reg, axis=1)
    test_std_reg = np.std(test_scores_reg, axis=1)
    
    ax2.plot(train_sizes_reg, train_mean_reg, 'o-', color='blue', label='Training score')
    ax2.plot(train_sizes_reg, test_mean_reg, 'o-', color='red', label='Cross-validation score')
    ax2.fill_between(train_sizes_reg, train_mean_reg - train_std_reg, train_mean_reg + train_std_reg, alpha=0.1, color='blue')
    ax2.fill_between(train_sizes_reg, test_mean_reg - test_std_reg, test_mean_reg + test_std_reg, alpha=0.1, color='red')
    ax2.set_xlabel('Training Set Size', fontsize=12, fontweight='bold')
    ax2.set_ylabel('R² Score', fontsize=12, fontweight='bold')
    ax2.set_title('Learning Curve - Urgency Predictor', fontsize=13, fontweight='bold', pad=15)
    ax2.legend(loc='lower right', fontsize=10)
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'learning_curves.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: learning_curves.png")


def plot_regression_performance(predictor, X_test, y_test, output_dir: str):
    """Plot regression performance: actual vs predicted."""
    print("Generating regression performance plots...")
    
    y_pred = predictor.predict(X_test)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Scatter plot: Actual vs Predicted
    ax1.scatter(y_test, y_pred, alpha=0.5, s=30, color='steelblue', edgecolors='black', linewidth=0.5)
    ax1.plot([y_test.min(), y_test.max()], [y_test.min(), y_test.max()], 'r--', lw=2, label='Perfect Prediction')
    ax1.set_xlabel('Actual Urgency Score', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Predicted Urgency Score', fontsize=12, fontweight='bold')
    ax1.set_title('Actual vs Predicted Urgency Scores', fontsize=13, fontweight='bold', pad=15)
    ax1.legend(fontsize=10)
    ax1.grid(True, alpha=0.3)
    
    # Calculate R²
    from sklearn.metrics import r2_score, mean_absolute_error, mean_squared_error
    r2 = r2_score(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    
    ax1.text(0.05, 0.95, f'R² = {r2:.4f}\nMAE = {mae:.2f}\nRMSE = {rmse:.2f}', 
             transform=ax1.transAxes, fontsize=11, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    # Residual plot
    residuals = y_test - y_pred
    ax2.scatter(y_pred, residuals, alpha=0.5, s=30, color='coral', edgecolors='black', linewidth=0.5)
    ax2.axhline(y=0, color='r', linestyle='--', lw=2)
    ax2.set_xlabel('Predicted Urgency Score', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Residuals', fontsize=12, fontweight='bold')
    ax2.set_title('Residual Plot', fontsize=13, fontweight='bold', pad=15)
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'regression_performance.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: regression_performance.png")


def plot_metrics_comparison(model_dir: str, output_dir: str):
    """Compare train vs test metrics from saved JSON files."""
    print("Generating metrics comparison charts...")
    
    # Load metrics
    classifier_metrics_path = os.path.join(model_dir, 'classifier_metrics.json')
    predictor_metrics_path = os.path.join(model_dir, 'predictor_metrics.json')
    
    if not os.path.exists(classifier_metrics_path) or not os.path.exists(predictor_metrics_path):
        print("⚠ Metrics files not found, skipping comparison chart")
        return
    
    with open(classifier_metrics_path, 'r') as f:
        classifier_metrics = json.load(f)
    with open(predictor_metrics_path, 'r') as f:
        predictor_metrics = json.load(f)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Classification metrics
    metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
    train_values = [classifier_metrics['train'][m] for m in metrics]
    test_values = [classifier_metrics['test'][m] for m in metrics]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    ax1.bar(x - width/2, train_values, width, label='Train', color='steelblue', alpha=0.8)
    ax1.bar(x + width/2, test_values, width, label='Test', color='coral', alpha=0.8)
    ax1.set_xlabel('Metrics', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Score', fontsize=12, fontweight='bold')
    ax1.set_title('Classification Metrics Comparison', fontsize=13, fontweight='bold', pad=15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'], rotation=45, ha='right')
    ax1.legend(fontsize=11)
    ax1.set_ylim([0, 1.1])
    ax1.grid(axis='y', alpha=0.3)
    
    # Regression metrics
    metrics_reg = ['r2_score', 'mae', 'rmse']
    train_values_reg = [
        predictor_metrics['train']['r2_score'],
        predictor_metrics['train']['mae'] / 100,  # Normalize for visualization
        predictor_metrics['train']['rmse'] / 100
    ]
    test_values_reg = [
        predictor_metrics['test']['r2_score'],
        predictor_metrics['test']['mae'] / 100,
        predictor_metrics['test']['rmse'] / 100
    ]
    
    x_reg = np.arange(len(metrics_reg))
    
    ax2.bar(x_reg - width/2, train_values_reg, width, label='Train', color='steelblue', alpha=0.8)
    ax2.bar(x_reg + width/2, test_values_reg, width, label='Test', color='coral', alpha=0.8)
    ax2.set_xlabel('Metrics', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Score (R²) / Normalized Error', fontsize=12, fontweight='bold')
    ax2.set_title('Regression Metrics Comparison', fontsize=13, fontweight='bold', pad=15)
    ax2.set_xticks(x_reg)
    ax2.set_xticklabels(['R² Score', 'MAE/100', 'RMSE/100'])
    ax2.legend(fontsize=11)
    ax2.grid(axis='y', alpha=0.3)
    
    # Add actual values as text
    for i, (train_val, test_val) in enumerate(zip(train_values_reg, test_values_reg)):
        if i == 0:  # R² score
            ax2.text(i - width/2, train_val + 0.03, f'{train_val:.3f}', ha='center', fontsize=9, fontweight='bold')
            ax2.text(i + width/2, test_val + 0.03, f'{test_val:.3f}', ha='center', fontsize=9, fontweight='bold')
        else:  # MAE, RMSE (show original values)
            original_train = train_val * 100
            original_test = test_val * 100
            ax2.text(i - width/2, train_val + 0.03, f'{original_train:.1f}', ha='center', fontsize=9, fontweight='bold')
            ax2.text(i + width/2, test_val + 0.03, f'{original_test:.1f}', ha='center', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'metrics_comparison.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: metrics_comparison.png")


def plot_vulnerability_distribution(df, output_dir: str):
    """Plot distribution of vulnerabilities in dataset."""
    print("Generating vulnerability distribution plots...")
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Class distribution
    class_counts = df['is_vulnerable'].value_counts()
    colors = ['#2ecc71', '#e74c3c']
    ax1.pie(class_counts.values, labels=['Safe', 'Vulnerable'], autopct='%1.1f%%', 
            colors=colors, startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    ax1.set_title('Dataset Class Distribution', fontsize=14, fontweight='bold', pad=20)
    
    # Urgency score distribution
    vulnerable_df = df[df['is_vulnerable'] == 1]
    if len(vulnerable_df) > 0:
        ax2.hist(vulnerable_df['urgency_score'], bins=20, color='coral', alpha=0.7, edgecolor='black')
        ax2.axvline(vulnerable_df['urgency_score'].mean(), color='red', linestyle='--', 
                   linewidth=2, label=f'Mean: {vulnerable_df["urgency_score"].mean():.1f}')
        ax2.axvline(vulnerable_df['urgency_score'].median(), color='blue', linestyle='--', 
                   linewidth=2, label=f'Median: {vulnerable_df["urgency_score"].median():.1f}')
        ax2.set_xlabel('Urgency Score', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Frequency', fontsize=12, fontweight='bold')
        ax2.set_title('Urgency Score Distribution (Vulnerable Code)', fontsize=14, fontweight='bold', pad=20)
        ax2.legend(fontsize=11)
        ax2.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'data_distribution.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved: data_distribution.png")


def main():
    parser = argparse.ArgumentParser(description='Generate ML model performance visualizations')
    parser.add_argument('--data', type=str, default='data/merged_all_datasets.csv',
                       help='Path to dataset CSV')
    parser.add_argument('--model-dir', type=str, default='models',
                       help='Directory containing trained models')
    parser.add_argument('--output-dir', type=str, default='visualizations',
                       help='Directory to save visualization plots')
    parser.add_argument('--test-size', type=float, default=0.2,
                       help='Proportion of data for testing')
    parser.add_argument('--random-seed', type=int, default=42,
                       help='Random seed for reproducibility')
    parser.add_argument('--skip-learning-curves', action='store_true',
                       help='Skip learning curves (saves time)')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"\n{'='*60}")
    print("ML Model Visualization Generator")
    print(f"{'='*60}\n")
    
    # Check if data file exists
    if not os.path.exists(args.data):
        print(f"Error: Dataset not found at {args.data}")
        print("Please provide a valid dataset path or run train.py first.")
        sys.exit(1)
    
    # Load models and data
    data = load_models_and_data(args.model_dir, args.data, args.test_size, args.random_seed)
    
    print(f"\nDataset: {len(data['df'])} samples")
    print(f"Training set: {len(data['X_train'])} samples")
    print(f"Test set: {len(data['X_test'])} samples\n")
    
    # Generate all visualizations
    print(f"Generating visualizations in '{args.output_dir}/'...\n")
    
    # 1. Confusion Matrix
    y_pred_class = data['classifier'].predict(data['X_test'])
    plot_confusion_matrix(data['y_class_test'], y_pred_class, args.output_dir)
    
    # 2. ROC Curve
    plot_roc_curve(data['classifier'], data['X_test'], data['y_class_test'], args.output_dir)
    
    # 3. Precision-Recall Curve
    plot_precision_recall_curve(data['classifier'], data['X_test'], data['y_class_test'], args.output_dir)
    
    # 4. Feature Importance (if available)
    plot_feature_importance(data['classifier'], data['extractor'], args.output_dir, top_n=20)
    
    # 5. Learning Curves (optional, takes more time)
    if not args.skip_learning_curves:
        X_combined = np.vstack([data['X_train'], data['X_test']])
        y_class_combined = np.concatenate([data['y_class_train'], data['y_class_test']])
        y_urgency_combined = np.concatenate([data['y_urgency_train'], data['y_urgency_test']])
        plot_learning_curves(data['classifier'], data['predictor'], 
                           X_combined, y_class_combined, y_urgency_combined, args.output_dir)
    
    # 6. Regression Performance
    plot_regression_performance(data['predictor'], data['X_test'], data['y_urgency_test'], args.output_dir)
    
    # 7. Metrics Comparison
    plot_metrics_comparison(args.model_dir, args.output_dir)
    
    # 8. Data Distribution
    plot_vulnerability_distribution(data['df'], args.output_dir)
    
    print(f"\n{'='*60}")
    print(f"✓ All visualizations saved to '{args.output_dir}/'")
    print(f"{'='*60}\n")
    
    print("Generated plots:")
    print("  • confusion_matrix.png - Classification confusion matrix")
    print("  • roc_curve.png - ROC curve with AUC score")
    print("  • precision_recall_curve.png - Precision-Recall curve")
    print("  • feature_importance.png - Top 20 important features (if available)")
    if not args.skip_learning_curves:
        print("  • learning_curves.png - Model learning curves")
    print("  • regression_performance.png - Actual vs predicted & residuals")
    print("  • metrics_comparison.png - Train vs test metrics comparison")
    print("  • data_distribution.png - Dataset and urgency distribution")
    print()


if __name__ == '__main__':
    main()
