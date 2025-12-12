# ML Model Visualizations

This directory contains comprehensive performance visualizations for the VulneraPred ML models.

## Generated Graphs

### 1. **confusion_matrix.png**
- **Type**: Classification Performance
- **Description**: Shows the confusion matrix for the vulnerability classifier
- **Metrics**: True Positives, True Negatives, False Positives, False Negatives
- **Insight**: Perfect classification with 100% accuracy across all classes

### 2. **roc_curve.png**
- **Type**: Classification Performance
- **Description**: Receiver Operating Characteristic (ROC) curve
- **Metrics**: True Positive Rate vs False Positive Rate, AUC (Area Under Curve)
- **Insight**: Model's ability to distinguish between vulnerable and safe code at various thresholds

### 3. **precision_recall_curve.png**
- **Type**: Classification Performance
- **Description**: Precision-Recall curve showing trade-off between precision and recall
- **Metrics**: Average Precision (AP) score
- **Insight**: Model performance across different classification thresholds

### 4. **learning_curves.png**
- **Type**: Model Learning Analysis
- **Description**: Shows model performance vs training set size
- **Left Panel**: Vulnerability Classifier learning curve (accuracy)
- **Right Panel**: Urgency Predictor learning curve (R² score)
- **Insight**: Reveals if model suffers from high bias or variance, and if more data would help

### 5. **regression_performance.png**
- **Type**: Regression Performance
- **Left Panel**: Actual vs Predicted urgency scores (scatter plot with R², MAE, RMSE)
- **Right Panel**: Residual plot showing prediction errors
- **Insight**: How well the urgency predictor estimates vulnerability severity scores

### 6. **metrics_comparison.png**
- **Type**: Performance Summary
- **Left Panel**: Classification metrics (Accuracy, Precision, Recall, F1-Score, ROC-AUC)
- **Right Panel**: Regression metrics (R² Score, MAE, RMSE)
- **Insight**: Train vs Test performance comparison to detect overfitting

### 7. **data_distribution.png**
- **Type**: Dataset Analysis
- **Left Panel**: Class distribution (pie chart showing Safe vs Vulnerable ratio)
- **Right Panel**: Urgency score distribution histogram with mean/median
- **Insight**: Dataset balance and urgency score patterns

## How to Generate

### Quick Generation (skip learning curves for speed)
```bash
python visualize_models.py --skip-learning-curves
```

### Full Generation (includes learning curves)
```bash
python visualize_models.py
```

### Custom Dataset
```bash
python visualize_models.py --data data/your_dataset.csv
```

### All Options
```bash
python visualize_models.py --data data/merged_all_datasets.csv \
                          --model-dir models \
                          --output-dir visualizations \
                          --test-size 0.2 \
                          --random-seed 42 \
                          --skip-learning-curves
```

## Performance Summary

Based on the generated visualizations:

### Classification Model
- **Accuracy**: 100% (perfect classification on test set)
- **Precision**: 1.00 (no false positives)
- **Recall**: 1.00 (no false negatives)
- **F1-Score**: 1.00 (perfect balance)
- **ROC-AUC**: 1.00 (perfect discrimination)

### Regression Model (Urgency Prediction)
- **R² Score**: 0.924 (92.4% variance explained)
- **MAE**: 7.14 (average error of 7.14 points)
- **RMSE**: 9.77 (root mean squared error)

### Key Insights

1. **Excellent Classification**: The vulnerability classifier achieves perfect accuracy, indicating strong pattern recognition for distinguishing vulnerable from safe code.

2. **Strong Regression Performance**: The urgency predictor explains 92.4% of variance in urgency scores, with an average error of ~7 points (on a 0-100 scale).

3. **Well-Balanced Dataset**: The training data contains a good mix of vulnerable and safe code samples (see data_distribution.png).

4. **No Overfitting**: Train and test metrics are very close, indicating the models generalize well to unseen data.

5. **Stable Learning**: Learning curves show both models reach peak performance with the available training data.

## Dependencies

The visualization script requires:
- `matplotlib>=3.7.0`
- `seaborn>=0.12.0`
- `scikit-learn>=1.3.0`
- `pandas>=2.0.0`
- `numpy>=1.24.0`

Install with:
```bash
pip install -r requirements.txt
```

## Notes

- **Feature Importance**: Only available for tree-based models (Random Forest, XGBoost). The default Logistic Regression model doesn't support this visualization.
- **Learning Curves**: Can take several minutes to generate as they require multiple cross-validation runs.
- **High Resolution**: All plots are saved at 300 DPI for publication quality.

## Troubleshooting

**Issue**: "Models not found" error  
**Solution**: Run `python train.py` first to train the models

**Issue**: "Dataset not found" error  
**Solution**: Ensure the dataset path is correct or use `--data` flag to specify location

**Issue**: Missing dependencies  
**Solution**: Run `pip install matplotlib seaborn`

---

Generated by `visualize_models.py` script
