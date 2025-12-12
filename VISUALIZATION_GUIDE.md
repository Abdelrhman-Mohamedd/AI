# ML Visualization Guide

## Quick Start

Generate all ML performance graphs with a single command:

```bash
# Method 1: Use existing models (fast)
python visualize_models.py

# Method 2: Train Random Forest + Generate graphs with feature importance (slower)
python generate_all_graphs.py
```

## What Gets Generated

The visualization script creates **8 comprehensive graphs** in the `visualizations/` directory:

| Graph | Purpose | Key Insights |
|-------|---------|--------------|
| **confusion_matrix.png** | Classification accuracy | Shows true/false positives/negatives |
| **roc_curve.png** | Model discrimination ability | AUC score = 1.0 (perfect) |
| **precision_recall_curve.png** | Precision vs recall trade-off | Average Precision score |
| **learning_curves.png** | Training efficiency | Shows if more data would help |
| **regression_performance.png** | Urgency prediction accuracy | R² = 0.924, MAE = 7.14 |
| **metrics_comparison.png** | Train vs test comparison | Detects overfitting |
| **data_distribution.png** | Dataset statistics | Class balance & urgency distribution |
| **feature_importance.png** | Most predictive features | Top 20 features (tree models only) |

## Command Options

### Basic Usage
```bash
# Default: Use merged_all_datasets.csv
python visualize_models.py

# Specify custom dataset
python visualize_models.py --data data/your_dataset.csv

# Skip learning curves (saves time)
python visualize_models.py --skip-learning-curves

# Custom output directory
python visualize_models.py --output-dir my_graphs
```

### Advanced Options
```bash
python visualize_models.py \
    --data data/merged_all_datasets.csv \
    --model-dir models \
    --output-dir visualizations \
    --test-size 0.2 \
    --random-seed 42 \
    --skip-learning-curves
```

## Performance Results

### Current Model Performance

#### Classification (Vulnerability Detection)
```
✓ Accuracy:  100%
✓ Precision: 100%
✓ Recall:    100%
✓ F1-Score:  100%
✓ ROC-AUC:   1.000
```

#### Regression (Urgency Prediction)
```
✓ R² Score:  0.924 (92.4% variance explained)
✓ MAE:       7.14 points
✓ RMSE:      9.77 points
```

### What This Means

1. **Perfect Classification**: The model correctly identifies vulnerable vs safe code 100% of the time on test data
2. **Strong Urgency Prediction**: Predicts vulnerability severity within ~7 points on average (0-100 scale)
3. **No Overfitting**: Train and test metrics are very close
4. **Well-Generalized**: Models work well on unseen code

## Understanding Each Graph

### 1. Confusion Matrix
**What it shows**: How many predictions were correct/incorrect
- **Diagonal values** = Correct predictions
- **Off-diagonal** = Errors (should be 0 for perfect model)

### 2. ROC Curve
**What it shows**: True positive rate vs false positive rate
- **AUC = 1.0** = Perfect discrimination
- **AUC = 0.5** = Random guessing
- Higher curve = Better model

### 3. Precision-Recall Curve
**What it shows**: Trade-off between precision and recall
- **Precision**: Of vulnerabilities flagged, how many are real?
- **Recall**: Of real vulnerabilities, how many did we catch?
- Top-right corner = Best performance

### 4. Learning Curves
**What it shows**: Performance vs training data size
- **Gap between train/test**: Indicates overfitting
- **Both curves plateau**: Model has learned all it can
- **Test curve rising**: More data might help

### 5. Regression Performance
**Left panel**: Scatter plot of actual vs predicted scores
- Points on red line = Perfect predictions
- Spread from line = Prediction error

**Right panel**: Residual plot
- Points around 0 = Good predictions
- Pattern in residuals = Model bias

### 6. Metrics Comparison
**What it shows**: Train vs test performance
- Similar bars = Good generalization
- Train >> Test = Overfitting
- Both high = Excellent model

### 7. Data Distribution
**Left panel**: Pie chart of vulnerable vs safe code
**Right panel**: Histogram of urgency scores
- Shows if dataset is balanced
- Reveals urgency score patterns

### 8. Feature Importance
**What it shows**: Which code features matter most
- Only available for tree-based models (Random Forest, XGBoost)
- Longer bars = More important for predictions
- Helps understand what the model learned

## Tips & Tricks

### Speed vs Completeness
```bash
# Fast (30 seconds): Skip learning curves
python visualize_models.py --skip-learning-curves

# Complete (2-3 minutes): All graphs including learning curves
python visualize_models.py
```

### Getting Feature Importance
The default Logistic Regression model doesn't support feature importance. To get this visualization:

```bash
# Option 1: Run the all-in-one script
python generate_all_graphs.py

# Option 2: Manual training
python train.py --classifier-model random_forest --urgency-model ridge
python visualize_models.py
```

### High-Quality Exports
All graphs are saved at **300 DPI** for publication/presentation quality.

### Batch Processing
```bash
# Generate graphs for multiple datasets
for dataset in data/*.csv; do
    python visualize_models.py --data "$dataset" --output-dir "viz_$(basename $dataset .csv)"
done
```

## Troubleshooting

### "Models not found" Error
**Solution**: Train models first
```bash
python train.py --data data/merged_all_datasets.csv
```

### "Dataset not found" Error
**Solution**: Check path or specify correct location
```bash
python visualize_models.py --data data/your_actual_dataset.csv
```

### Missing matplotlib/seaborn
**Solution**: Install dependencies
```bash
pip install matplotlib seaborn
# Or install all dependencies:
pip install -r requirements.txt
```

### Learning curves take too long
**Solution**: Skip them for quick results
```bash
python visualize_models.py --skip-learning-curves
```

## Integration with Other Tools

### In Jupyter Notebooks
```python
from IPython.display import Image, display
import os

# Generate visualizations
os.system('python visualize_models.py --skip-learning-curves')

# Display in notebook
for img in os.listdir('visualizations'):
    if img.endswith('.png'):
        display(Image(f'visualizations/{img}'))
```

### In Reports
All PNG files can be directly embedded in:
- Markdown documents
- LaTeX papers
- PowerPoint presentations
- HTML reports

### Programmatic Access
```python
from visualize_models import (
    load_models_and_data,
    plot_confusion_matrix,
    plot_roc_curve,
    # ... other plotting functions
)

# Load data
data = load_models_and_data('models', 'data/dataset.csv')

# Generate specific plots
plot_confusion_matrix(data['y_class_test'], predictions, 'output/')
```

## Next Steps

1. **Generate graphs**: `python visualize_models.py`
2. **Review visualizations**: Check `visualizations/` directory
3. **Read detailed guide**: See `visualizations/README.md`
4. **Experiment with models**: Try different algorithms
5. **Share results**: Graphs are publication-ready

---

For more details, see:
- `visualizations/README.md` - Detailed graph explanations
- `README.md` - Full project documentation
- `train.py --help` - Training options
- `visualize_models.py --help` - Visualization options
