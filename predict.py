import joblib
import pandas as pd

from config import MODEL_PATH, PHISHING_THRESHOLD, ENABLE_WHOIS_LOOKUP
from feature_extractor import explain_url_risk, extract_url_features
from blacklist_checker import check_blacklist
from whois_checker import get_domain_age_days


def load_model():
    return joblib.load(MODEL_PATH)


def calculate_final_risk_score(ml_probability, blacklist_result, whois_result):
    risk = ml_probability * 100

    if blacklist_result.get("is_blacklisted"):
        risk += 25

    domain_age_days = whois_result.get("domain_age_days", -1)

    if domain_age_days != -1 and domain_age_days < 30:
        risk += 15
    elif domain_age_days != -1 and domain_age_days < 90:
        risk += 8

    return round(min(risk, 100), 2)


def predict_url(url: str) -> dict:
    model = load_model()

    input_df = pd.DataFrame({"url": [url]})

    raw_prediction = int(model.predict(input_df)[0])
    probability = float(model.predict_proba(input_df)[0][1])

    blacklist_result = check_blacklist(url)

    if ENABLE_WHOIS_LOOKUP:
        whois_result = get_domain_age_days(url)
    else:
        whois_result = {
            "domain": blacklist_result["domain"],
            "domain_age_days": -1,
            "whois_available": False,
            "error": "WHOIS lookup disabled"
        }

    final_risk_score = calculate_final_risk_score(
        probability,
        blacklist_result,
        whois_result
    )

    final_prediction = "PHISHING" if final_risk_score >= PHISHING_THRESHOLD * 100 else "LEGITIMATE"

    extra_context = {
        "is_blacklisted": blacklist_result.get("is_blacklisted"),
        "domain_age_days": whois_result.get("domain_age_days", -1)
    }

    reasons = explain_url_risk(url, probability, extra_context)

    return {
        "url": url,
        "prediction": final_prediction,
        "ml_prediction": "PHISHING" if raw_prediction == 1 else "LEGITIMATE",
        "risk_score": final_risk_score,
        "ml_phishing_probability": round(probability, 4),
        "blacklist": blacklist_result,
        "whois": whois_result,
        "features": extract_url_features(url),
        "reasons": reasons
    }


if __name__ == "__main__":
    test_url = input("Enter URL: ").strip()
    result = predict_url(test_url)

    print("\n===== PHISHING DETECTION RESULT =====")
    print(f"URL: {result['url']}")
    print(f"Final Prediction: {result['prediction']}")
    print(f"ML Prediction: {result['ml_prediction']}")
    print(f"Risk Score: {result['risk_score']}%")
    print(f"ML Phishing Probability: {result['ml_phishing_probability']}")

    print("\nBlacklist:")
    print(result["blacklist"])

    print("\nWHOIS:")
    print(result["whois"])

    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")