import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

def train():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(current_dir, 'dataset.csv')
    model_path = os.path.join(current_dir, 'classifier.pkl')

    if not os.path.exists(dataset_path):
        print(f"Error: dataset.csv not found at {dataset_path}")
        return

    # Load dataset
    df = pd.read_csv(dataset_path)
    X = df['text']
    y = df['label']

    # Define Pipeline containing TF-IDF and Multinomial Naive Bayes with optimized hyperparameters
    pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(stop_words='english', min_df=1, ngram_range=(1, 1), sublinear_tf=True, use_idf=True)),
        ('classifier', MultinomialNB(alpha=0.01))
    ])

    print("Evaluating CipherGuard text classifier structure...")
    
    # Split dataset into train and test splits (stratified since we have 3 classes)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    # Train the pipeline on the training split
    pipeline.fit(X_train, y_train)
    
    # Predict on the test split
    y_pred = pipeline.predict(X_test)
    
    # Calculate evaluation metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    conf_matrix = confusion_matrix(y_test, y_pred, labels=['Public', 'Confidential', 'Secret'])
    
    print("-" * 50)
    print("Model Evaluation Metrics (Test Split):")
    print(f"  Accuracy  : {accuracy * 100:.2f}%")
    print(f"  Precision : {precision * 100:.2f}%")
    print(f"  Recall    : {recall * 100:.2f}%")
    print(f"  F1-Score  : {f1 * 100:.2f}%")
    print("-" * 50)
    print("Confusion Matrix:")
    print("                 Predicted")
    print("                 Pub  Conf  Sec")
    print(f"Actual Pub      [{conf_matrix[0][0]:3d}  {conf_matrix[0][1]:3d}  {conf_matrix[0][2]:3d}]")
    print(f"       Conf     [{conf_matrix[1][0]:3d}  {conf_matrix[1][1]:3d}  {conf_matrix[1][2]:3d}]")
    print(f"       Sec      [{conf_matrix[2][0]:3d}  {conf_matrix[2][1]:3d}  {conf_matrix[2][2]:3d}]")
    print("-" * 50)
    
    # Retrain pipeline on the complete dataset for production deploy
    print("Retraining final model on the full dataset...")
    pipeline.fit(X, y)
    
    # Save model pipeline
    joblib.dump(pipeline, model_path)
    print(f"Trained model saved successfully to: {model_path}")

if __name__ == "__main__":
    train()

