import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

from sklearn.metrics import confusion_matrix
from sklearn.metrics import precision_recall_fscore_support


def save_confusion_matrix(true_labels: list, predicted_labels: list, path: str):
    labels = list(set(true_labels + predicted_labels))

    cm = confusion_matrix(true_labels, predicted_labels, labels=labels)

    plt.figure(figsize=(18, 9))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.savefig(path)
    plt.close()


def print_precision_recall(true_labels: list, predicted_labels: list):
    labels = list(set(true_labels + predicted_labels))

    precision, recall, _, support = precision_recall_fscore_support(true_labels, predicted_labels, labels=labels, average=None)

    metrics_df = pd.DataFrame({
        'Class': labels,
        'Precision': precision,
        'Recall': recall,
        'Support': support
    })

    print(metrics_df.to_string(index=False))
