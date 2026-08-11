import os
import joblib

# Load classifier globally for efficiency in production
_pipeline = None

def get_pipeline():
    global _pipeline
    if _pipeline is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, 'classifier.pkl')
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Classifier model file not found at {model_path}. Please run train_model.py first.")
        _pipeline = joblib.load(model_path)
    return _pipeline

def classify_document(text):
    """
    Classifies a text document payload and calculates a DLP risk score.
    Returns a dictionary with 'classification', 'confidence', 'risk_score', and probabilities.
    """
    pipeline = get_pipeline()
    prediction = pipeline.predict([text])[0]
    
    # Extract prediction probability distributions
    probs = pipeline.predict_proba([text])[0]
    classes = pipeline.classes_
    prob_dict = dict(zip(classes, probs))
    
    # Confidence is the probability of the predicted class
    class_index = list(classes).index(prediction)
    confidence = round(float(probs[class_index]), 4)
    
    # Calculate a risk score from 0 to 10 based on sensitivity levels
    # Secret represents high risk (weight 10.0), Confidential represents moderate risk (weight 4.0)
    prob_secret = prob_dict.get('Secret', 0.0)
    prob_confidential = prob_dict.get('Confidential', 0.0)
    
    risk_score = (prob_secret * 10.0) + (prob_confidential * 4.0)
    # Clamp between 0.00 and 10.00
    risk_score = round(max(0.00, min(10.00, risk_score)), 2)

    return {
        "classification": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "probabilities": {cls: round(float(p), 4) for cls, p in prob_dict.items()}
    }

if __name__ == "__main__":
    # Test cases representing various levels of sensitivity
    test_cases = [
        "We are launching our new product campaign next quarter. Read our public prospectus.",
        "Here is the project outline for internal Q3 planning. Please keep this confidential within the core engineering team.",
        "DATABASE_PASSWORD = my_sql_db_root_2026_secured. Admin token: AKIAIOSFODNN7EXAMPLE."
    ]

    print("Executing sample classification predictions...\n")
    for text in test_cases:
        try:
            result = classify_document(text)
            print(f"Input: \"{text[:60]}...\"")
            print(f"  Classification : {result['classification']}")
            print(f"  Risk Score     : {result['risk_score']}/10.00")
            print(f"  Probabilities  : {result['probabilities']}")
            print("-" * 50)
        except Exception as e:
            print(f"Error during prediction: {e}")
