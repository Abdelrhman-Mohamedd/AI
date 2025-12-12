"""
Quick script to train with Random Forest and generate feature importance visualization.
"""

import os
import sys

print("Training models with Random Forest for feature importance visualization...")
print("=" * 60)

# Train with Random Forest
exit_code = os.system('python train.py --data data/merged_all_datasets.csv --classifier-model random_forest --urgency-model ridge')

if exit_code == 0:
    print("\n" + "=" * 60)
    print("Generating visualizations with feature importance...")
    print("=" * 60 + "\n")
    
    # Generate visualizations
    os.system('python visualize_models.py --data data/merged_all_datasets.csv --skip-learning-curves')
    
    print("\n" + "=" * 60)
    print("✓ Complete! Check 'visualizations/' folder for all graphs.")
    print("=" * 60)
else:
    print("\n⚠ Training failed. Please check the error messages above.")
    sys.exit(1)
