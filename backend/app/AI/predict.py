import os
import joblib
import re

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

def detect_security_indicators(text):
    """
    Scans document text against compiled regular expressions to identify security indicators.
    Returns a list of unique matched indicators.
    """
    detected = []
    
    # Financial information patterns
    financial_patterns = [
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card format
        r'(?i)\b(credit\s*card|bank\s*statement|transaction\s*record|financial\s*report|invoice\s*summary|wire\s*transfer|billing\s*statement)\b'
    ]
    for pattern in financial_patterns:
        if re.search(pattern, text):
            detected.append("Financial information")
            break
            
    # Email addresses
    if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text):
        detected.append("Email addresses")

    # Phone numbers
    if re.search(r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b', text):
        detected.append("Phone numbers")

    # Personal information patterns
    personal_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'(?i)\b(personally\s*identifiable|date\s*of\s*birth|\bdob\b|medical\s*record)\b'
    ]
    for pattern in personal_patterns:
        if re.search(pattern, text):
            detected.append("Personal information")
            break
            
    # Credentials (passwords, tokens, api keys, private keys)
    credentials_patterns = [
        r'(?i)\b(password\w*|passwd\w*|passphrase|db_password|admin_password|database_url|db_url|secret_key|jwt_secret|api_key|apikey|access_key|private_key|bearer)\b\s*[:=]\s*[\'"]?[A-Za-z0-9+/=_\-@:\.\/]{4,}["\']?',
        r'-----BEGIN\s+[A-Z ]+\s+PRIVATE\s+KEY-----',
        r'\b(AKIA[0-9A-Z]{16})\b',
        r'(?i)aws_secret_access_key',
        r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b',
        r'\bxox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}\b'
    ]
    for pattern in credentials_patterns:
        if re.search(pattern, text):
            detected.append("Credentials")
            break
 
    # Account numbers
    account_patterns = [
        r'(?i)\b(account\s*number|routing\s*number|iban|swift|sort\s*code|bank\s*account)\b',
        r'(?i)\b(account|routing)\s+\d{6,18}\b'
    ]
    for pattern in account_patterns:
        if re.search(pattern, text):
            detected.append("Account numbers")
            break
 
    # Government identifiers
    gov_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
        r'(?i)\b(ssn|social\s*security|national\s*id|driver\'s\s*license|tax\s*id(entification)?)\b',
        r'(?i)\bpassport\s*:\s*[A-Z0-9]{9}\b'
    ]
    for pattern in gov_patterns:
        if re.search(pattern, text):
            detected.append("Government identifiers")
            break
 
    # Confidential keywords & Corporate terms
    conf_patterns = [
        r'(?i)\b(confidential|proprietary|internal|trade\s*secret|do\s*not\s*(distribute|share)|restricted|classified|secret)\b',
        r'(?i)\b(acquisition\s*draft|board\s*resolution|merger\s*terms|employment\s*agreement|nda|non-disclosure|salary\s*sheet|undisclosed)\b'
    ]
    for pattern in conf_patterns:
        if re.search(pattern, text):
            detected.append("Confidential keywords")
            break
 
    return detected

def classify_document(text):
    """
    Classifies a text document using a hybrid scoring pipeline:
    1. Machine Learning prediction (TF-IDF + Multinomial Naive Bayes).
    2. Lightweight rule-based security indicator analysis.
    3. Multi-tier classification overrides.
    Returns:
      category (uppercase: PUBLIC, CONFIDENTIAL, or SECRET)
      confidence (float percentage: 0.0 - 100.0)
      detected_indicators (list of strings)
      ml_category (uppercase string)
      ml_confidence (float percentage)
      override_applied (boolean)
      explanation (string description of the classification decision)
      risk_score (backward-compatible, float: 0.0 - 10.0)
      probabilities (dict of classes and floats)
    """
    pipeline = get_pipeline()
    
    # 1. Run Machine Learning predictions
    ml_prediction = pipeline.predict([text])[0]  # Standard labels: 'Public', 'Confidential', 'Secret'
    probs = pipeline.predict_proba([text])[0]
    classes = pipeline.classes_
    prob_dict = dict(zip(classes, probs))
    
    ml_class_index = list(classes).index(ml_prediction)
    ml_confidence = float(probs[ml_class_index])
    
    # 2. Run rule-based security indicator scan
    detected_indicators = detect_security_indicators(text)
    
    # 3. Apply transparent override/upgrade scoring logic
    ml_cat_upper = ml_prediction.upper()
    ml_conf_pct = round(ml_confidence * 100.0, 2)
    
    category = ml_cat_upper
    confidence_fraction = ml_confidence

    # Tier A override: High-severity indicators force SECRET
    if "Credentials" in detected_indicators or "Government identifiers" in detected_indicators:
        category = "SECRET"
        confidence_fraction = 0.99  # Forced high confidence for pattern-matched secrets
    # Tier B override: Moderate-severity indicators force CONFIDENTIAL (unless already SECRET)
    elif detected_indicators:
        if category != "SECRET":
            category = "CONFIDENTIAL"
            confidence_fraction = max(0.95, ml_confidence) # Forced high confidence floor

    # Calculate backward-compatible risk score (0 to 10 scale)
    prob_secret = prob_dict.get('Secret', 0.0)
    prob_confidential = prob_dict.get('Confidential', 0.0)
    
    if category == "SECRET":
        risk_score = max(9.8, (prob_secret * 10.0) + (prob_confidential * 4.0))
    elif category == "CONFIDENTIAL":
        risk_score = max(5.0, (prob_secret * 10.0) + (prob_confidential * 4.0))
    else:
        risk_score = (prob_secret * 10.0) + (prob_confidential * 4.0)
        
    risk_score = round(max(0.00, min(10.00, risk_score)), 2)
    confidence = round(float(confidence_fraction * 100), 2)
    override_applied = (category != ml_cat_upper)

    # Construct dynamic, transparent explanation
    if override_applied:
        explanation = (
            f"Machine Learning model predicted '{ml_cat_upper}' with {ml_conf_pct}% confidence. "
            f"However, rule-based Security Indicator Analysis detected sensitive patterns: {', '.join(detected_indicators)}. "
            f"This triggered a safety override, upgrading the final classification to '{category}' with {confidence}% confidence."
        )
    elif len(detected_indicators) > 0:
        explanation = (
            f"Machine Learning model predicted '{ml_cat_upper}' with {ml_conf_pct}% confidence. "
            f"Rule-based Security Indicator Analysis also detected matching indicators: {', '.join(detected_indicators)}. "
            f"Both models align, resulting in a final classification of '{category}' with {confidence}% confidence."
        )
    else:
        explanation = (
            f"Machine Learning model predicted '{ml_cat_upper}' with {ml_conf_pct}% confidence. "
            f"No sensitive rule-based indicators were detected. "
            f"Final classification remains '{category}' with {confidence}% confidence."
        )

    return {
        "category": category,
        "confidence": confidence,
        "detected_indicators": detected_indicators,
        "ml_category": ml_cat_upper,
        "ml_confidence": ml_conf_pct,
        "override_applied": override_applied,
        "explanation": explanation,
        "risk_score": risk_score,
        "probabilities": {cls: round(float(p), 4) for cls, p in prob_dict.items()}
    }


if __name__ == "__main__":
    # Test cases representing various levels of sensitivity
    test_cases = [
        "We are launching our new product campaign next quarter. Read our public prospectus.",
        "Here is the project outline for internal Q3 planning. Please keep this confidential within the core engineering team.",
        "DATABASE_PASSWORD = my_sql_db_root_2026_secured. Admin token: AKIAIOSFODNN7EXAMPLE.",
        "Confidential client account records. Primary target: routing number 121000248, account 998273291."
    ]

    print("Executing sample classification predictions...\n")
    for text in test_cases:
        try:
            result = classify_document(text)
            print(f"Input: \"{text[:60]}...\"")
            print(f"  Category            : {result['category']}")
            print(f"  Confidence          : {result['confidence']}%")
            print(f"  Detected Indicators : {result['detected_indicators']}")
            print(f"  Risk Score          : {result['risk_score']}/10.00")
            print("-" * 50)
        except Exception as e:
            print(f"Error during prediction: {e}")

