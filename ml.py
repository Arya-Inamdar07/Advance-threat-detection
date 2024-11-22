import pandas as pd
import numpy as np
import pickle
from sklearn import ensemble
from sklearn import model_selection
from sklearn.feature_selection import SelectFromModel
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.dummy import DummyClassifier
import os
import tkinter as tk
from tkinter import messagebox, filedialog
import matplotlib.pyplot as plt
import seaborn as sns

# Load dataset function
def load_data(file_path):
    try:
        data = pd.read_csv(file_path, sep='|', engine='python')
        X = data.drop(['Name', 'md5', 'legitimate'], axis=1).values
        y = data['legitimate'].values
        return data, X, y
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load data: {e}")
        return None, None, None

# Function to visualize the confusion matrix
def plot_confusion_matrix(cm, classes, title='Confusion Matrix'):
    plt.figure(figsize=(6, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
    plt.title(title)
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.show()

# Function to run machine learning models
def run_ml():
    file_path = filedialog.askopenfilename(title="Select Data File", filetypes=(("CSV Files", "*.csv"),))
    if not file_path:
        return
    
    data, X, y = load_data(file_path)
    if X is None or y is None:
        return
    
    # Feature Selection
    fsel = ensemble.ExtraTreesClassifier().fit(X, y)
    model = SelectFromModel(fsel, prefit=True)
    X_new = model.transform(X)
    nb_features = X_new.shape[1]

    # Display important features
    features = []
    indices = np.argsort(fsel.feature_importances_)[::-1][:nb_features]
    original_features = data.columns.drop(['Name', 'md5', 'legitimate'])
    for f in range(nb_features):
        feature_name = original_features[indices[f]]
        feature_importance = fsel.feature_importances_[indices[f]]
        print(f"{f + 1}. feature {feature_name} ({feature_importance:.6f})")
        features.append(feature_name)

    # Split Dataset
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X_new, y, test_size=0.2, random_state=42)

    # Define Algorithms
    algorithms = {
        "DecisionTree": DecisionTreeClassifier(max_depth=10),
        "RandomForest": ensemble.RandomForestClassifier(n_estimators=50),
        "GradientBoosting": ensemble.GradientBoostingClassifier(n_estimators=50),
        "AdaBoost": ensemble.AdaBoostClassifier(n_estimators=100),
        "GNB": GaussianNB(),
        "Baseline": DummyClassifier(strategy='most_frequent')
    }

    # Evaluate Algorithms
    results = {}
    threshold = 0.90
    for algo_name, clf in algorithms.items():
        clf.fit(X_train, y_train)
        score = clf.score(X_test, y_test)
        results[algo_name] = score

    # Identify the Best Algorithm
    qualified_algos = {k: v for k, v in results.items() if v >= threshold}
    if qualified_algos:
        winner = max(qualified_algos, key=qualified_algos.get)
        print(f"\nWinner algorithm is {winner} with a {results[winner] * 100:.2f}% success rate")
        messagebox.showinfo("Result", f"Winner algorithm is {winner} with a {results[winner] * 100:.2f}% success rate")
    else:
        best_algo = max(results, key=results.get)
        print(f"\nNo algorithm met the threshold of {threshold * 100:.2f}%. Best performing algorithm was {best_algo} with {results[best_algo] * 100:.2f}% accuracy.")
        messagebox.showinfo("Result", f"No algorithm met the threshold. Best performing algorithm was {best_algo} with {results[best_algo] * 100:.2f}% accuracy.")

    # Save and Evaluate the Best Model
    if qualified_algos:
        if not os.path.exists('classifier'):
            os.makedirs('classifier')
        pickle.dump(algorithms[winner], open('classifier/classifier.pkl', 'wb'))
        pickle.dump(features, open('classifier/features.pkl', 'wb'))
        messagebox.showinfo("Info", "Model and features saved successfully!")

        clf = algorithms[winner]
        predictions = clf.predict(X_test)
        conf_matrix = confusion_matrix(y_test, predictions)
        false_positive_rate = (conf_matrix[0][1] / float(sum(conf_matrix[0]))) * 100
        false_negative_rate = (conf_matrix[1][0] / float(sum(conf_matrix[1]))) * 100

        messagebox.showinfo("Metrics", f"False positive rate: {false_positive_rate:.2f}%\nFalse negative rate: {false_negative_rate:.2f}%")

        # Show the Confusion Matrix
        plot_confusion_matrix(conf_matrix, classes=['Legitimate', 'Malicious'])
    else:
        messagebox.showwarning("Warning", "No model was saved due to unsatisfactory performance.")

# GUI Setup
root = tk.Tk()
root.title("Advance threat detection system")
root.geometry("400x200")

frame = tk.Frame(root)
frame.pack(pady=20)

btn = tk.Button(frame, text="Run Machine Learning Model", command=run_ml)
btn.pack()

root.mainloop()
