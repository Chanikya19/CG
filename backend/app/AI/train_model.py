import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
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

    # Define Pipeline containing TF-IDF and Multinomial Naive Bayes
    pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(stop_words='english', min_df=1, ngram_range=(1, 2))),
        ('classifier', MultinomialNB())
    ])

    print("Training CipherGuard text classifier...")
    pipeline.fit(X, y)
    
    # Save model pipeline
    joblib.dump(pipeline, model_path)
    print(f"Trained model saved successfully to: {model_path}")

if __name__ == "__main__":
    train()
