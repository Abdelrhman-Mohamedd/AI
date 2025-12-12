"""
Utility functions for the vulnerability prediction system.
"""

import os
import json
from typing import Dict, Any


def ensure_dir(directory: str) -> None:
    """
    Create directory if it doesn't exist.
    
    Args:
        directory: Directory path to create
    """
    os.makedirs(directory, exist_ok=True)


def save_metrics(metrics: Dict[str, Any], output_path: str) -> None:
    """
    Save evaluation metrics to JSON file.
    
    Args:
        metrics: Dictionary of metric names and values
        output_path: Path to save JSON file
    """
    ensure_dir(os.path.dirname(output_path) if os.path.dirname(output_path) else '.')
    
    with open(output_path, 'w') as f:
        json.dump(metrics, f, indent=2)


def load_metrics(input_path: str) -> Dict[str, Any]:
    """
    Load evaluation metrics from JSON file.
    
    Args:
        input_path: Path to JSON file
        
    Returns:
        Dictionary of metric names and values
    """
    with open(input_path, 'r') as f:
        return json.load(f)


def print_metrics(metrics: Dict[str, Any], title: str = "Metrics") -> None:
    """
    Pretty print metrics to console.
    
    Args:
        metrics: Dictionary of metric names and values
        title: Title to display
    """
    print(f"\n{'='*50}")
    print(f"{title:^50}")
    print(f"{'='*50}")
    
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"{key:30s}: {value:>10.4f}")
        else:
            print(f"{key:30s}: {value:>10}")
    
    print(f"{'='*50}\n")


def format_vulnerability_result(
    is_vulnerable: bool, 
    vulnerability_score: float, 
    urgency_score: float
) -> str:
    """
    Format prediction results as human-readable string.
    
    Args:
        is_vulnerable: Whether code is classified as vulnerable
        vulnerability_score: Probability of being vulnerable (0-1)
        urgency_score: Urgency score (0-100)
        
    Returns:
        Formatted result string
    """
    status = "VULNERABLE" if is_vulnerable else "SAFE"
    confidence = vulnerability_score * 100
    
    result = f"""
╔{'='*58}╗
║ VULNERABILITY ANALYSIS RESULT                            ║
╠{'='*58}╣
║ Status:              {status:40s} ║
║ Confidence:          {confidence:6.2f}%                               ║
║ Urgency Score:       {urgency_score:6.2f}/100                          ║
║                                                          ║
║ Interpretation:                                          ║
"""
    
    if urgency_score >= 80:
        priority = "CRITICAL - Immediate action required"
    elif urgency_score >= 60:
        priority = "HIGH - Should be fixed soon"
    elif urgency_score >= 40:
        priority = "MEDIUM - Schedule fix in next sprint"
    elif urgency_score >= 20:
        priority = "LOW - Address when convenient"
    else:
        priority = "MINIMAL - Optional improvement"
    
    result += f"║   Priority: {priority:45s} ║\n"
    result += f"╚{'='*58}╝\n"
    
    return result
