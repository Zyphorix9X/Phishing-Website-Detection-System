"""URL-only inference using the preserved Random Forest pipeline."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from config import MODEL_METADATA_PATH, MODEL_PATH, PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD
from feature_extractor import extract_url_features
from phishing_app.services.domain_intelligence import get_domain_intelligence
from phishing_app.services.threat_intelligence import check_threat_intelligence
from url_indicators import assess_url_indicators
from risk_summary import summarize_risk

logger = logging.getLogger(__name__)


class ModelUnavailableError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_model():
    if not Path(MODEL_PATH).is_file():
        raise ModelUnavailableError("Trained model file is not present.")
    try:
        return joblib.load(MODEL_PATH)
    except Exception as exc:
        logger.exception("The trained model could not be loaded")
        raise ModelUnavailableError("The trained model is incompatible with this runtime.") from exc


def load_model_metadata() -> dict:
    try:
        return json.loads(Path(MODEL_METADATA_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # Existing training files contain PhiUSIIL's source labels. The UCI
        # dataset defines 0 as phishing and 1 as legitimate.
        return {
            "model_version": "legacy-phiusiil-labels",
            "positive_class_label": 0,
            "class_meanings": {"0": "phishing", "1": "legitimate"},
            "mapping_source": "UCI PhiUSIIL source labels",
            "deployment_status": "research_only",
        }


def calculate_final_risk_score(ml_probability, blacklist_result, whois_result, features=None, *, indicator_score=None) -> float:
    """Return a transparent heuristic index, never a probability."""
    score = round(max(0.0, min(1.0, float(ml_probability))) * 60) if ml_probability is not None else 0
    if indicator_score is not None:
        return float(min(100, score + indicator_score))
    if blacklist_result.get("is_blacklisted"):
        score += 40
    if features:
        score += 18 if features.get("has_ip_address") else 0
        score += min(features.get("suspicious_word_count", 0), 3) * 5
        score += 6 if features.get("brand_keyword_count") and features.get("suspicious_word_count") else 0
        score += 5 if features.get("contains_percent_encoding") else 0
        score += 5 if features.get("contains_shortener_hint") else 0
        score += 4 if features.get("url_length", 0) > 100 else 0
        score += 5 if features.get("has_https") == 0 else 0
    domain_age = whois_result.get("domain_age_days") if whois_result else None
    if domain_age is not None and domain_age < 30:
        score += 10
    elif domain_age is not None and domain_age < 90:
        score += 5
    return float(min(score, 100))


def predict_url(
    url: str,
    *,
    rdap_enabled: bool = True,
    phishtank_api_key: str = "",
    openphish_feed_url: str = "",
) -> dict:
    """Analyze a normalized URL without opening or fetching the submitted URL."""
    from phishing_app.validation import normalize_url

    normalized = normalize_url(url)
    metadata = load_model_metadata()
    model_validated = metadata.get('deployment_status') == 'validated'
    model_warning = '' if model_validated else metadata.get('deployment_warning',
        'This model has not passed independent deployment validation. Its score alone cannot establish whether a URL is phishing or legitimate.')
    features = extract_url_features(normalized)
    threat_results = check_threat_intelligence(normalized, phishtank_api_key, openphish_feed_url)
    confirmed_match = any(item.get("matched") for item in threat_results)
    domain_result = get_domain_intelligence(normalized, enabled=rdap_enabled)

    model_status = "available"
    phishing_probability = None
    model_explanation = {"status": "unavailable", "method": None, "items": []}
    try:
        model = load_model()
        frame = pd.DataFrame({"url": [normalized]})
        classes = list(model.classes_) if hasattr(model, "classes_") else [0, 1]
        phishing_label = metadata.get("positive_class_label", 0)
        if not hasattr(model, "predict_proba"):
            raise ValueError("The loaded model does not provide class probabilities.")
        probabilities = model.predict_proba(frame)[0]
        probability_by_class = {label: float(probabilities[index]) for index, label in enumerate(classes)}
        phishing_probability = probability_by_class.get(phishing_label)
        if phishing_probability is None:
            raise ValueError("Model metadata references a class that is not in the estimator.")
        model_explanation = _local_ablation_explanation(model, frame, phishing_label, phishing_probability)
    except ModelUnavailableError:
        model_status = "unavailable"
    except Exception:
        logger.exception("Inference failed for a URL analysis")
        model_status = "unavailable"
        phishing_probability = None

    assessment = assess_url_indicators(normalized, confirmed_match=confirmed_match, domain_age_days=domain_result.get('domain_age_days'))
    rule_reasons = [item['description'] for item in assessment['items']]
    ml_prediction = 'UNVERIFIED' if phishing_probability is None else ('PHISHING' if phishing_probability >= 0.5 else 'LEGITIMATE')
    if confirmed_match:
        verdict = 'PHISHING'
        decision_source = 'confirmed_threat_intelligence'
        decision_explanation = 'A configured threat source reported a confirmed match.'
    elif model_status == 'unavailable' or not model_validated:
        verdict = 'SUSPICIOUS' if assessment['requires_review'] else 'UNVERIFIED'
        decision_source = 'url_rules' if verdict == 'SUSPICIOUS' else 'insufficient_reliable_evidence'
        decision_explanation = ('URL indicators warrant review; there is no confirmed threat-source match.' if verdict == 'SUSPICIOUS'
            else 'Verification is incomplete: the available checks and unvalidated model cannot establish whether this URL is phishing or legitimate.')
    else:
        if phishing_probability >= PHISHING_THRESHOLD:
            verdict = "PHISHING"
        elif phishing_probability >= SUSPICIOUS_THRESHOLD or assessment['requires_review']:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"
        decision_source = 'validated_model_and_url_rules'
        decision_explanation = 'The validated model and configured URL rules determined this verdict; it is not a safety guarantee.'

    risk_score = calculate_final_risk_score(phishing_probability, {}, {}, indicator_score=assessment['score']) if model_validated and model_status == 'available' else None
    local_finding = next((item for item in threat_results if item["provider"] == "Local blacklist"), {})
    result = {
        "url": url,
        "normalized_url": normalized,
        "prediction": verdict,
        "ml_prediction": ml_prediction,
        "risk_score": risk_score,
        "url_indicator_score": assessment['score'],
        "url_indicators": assessment['items'],
        "hostname_keyword_count": assessment['hostname_keyword_count'],
        "ml_phishing_probability": round(phishing_probability, 6) if phishing_probability is not None else None,
        "ml_probability_calibrated": False,
        "model_status": model_status,
        "model_version": metadata.get("model_version", "unknown"),
        "model_deployment_status": metadata.get('deployment_status', 'research_only'),
        "model_warning": model_warning,
        "decision_source": decision_source,
        "decision_explanation": decision_explanation,
        "score_explanation": ('Heuristic index (0-100); not a probability or calibrated likelihood.' if model_validated
            else 'An overall risk rating is unavailable. Observed URL indicator points are shown separately and do not establish safety.'),
        "blacklist": local_finding | {"is_blacklisted": bool(local_finding.get("matched"))},
        "threat_intelligence": threat_results,
        "whois": domain_result,
        "features": features,
        "reasons": rule_reasons,
        "model_explanation": model_explanation,
        "screenshot_analysis": {"status": "unavailable", "message": "Isolated webpage analysis is disabled."},
    }
    result.update(summarize_risk(result))
    return result


def _local_ablation_explanation(model, frame: pd.DataFrame, phishing_label, baseline_probability: float) -> dict:
    """Explain a URL with Tree SHAP, falling back to actual-model ablation."""
    try:
        if not hasattr(model, "named_steps"):
            return {"status": "unavailable", "method": None, "items": []}
        transform = model.named_steps.get("features")
        classifier = model.named_steps.get("classifier")
        if transform is None or classifier is None or not hasattr(classifier, "feature_importances_"):
            return {"status": "unavailable", "method": None, "items": []}
        transformed = transform.transform(frame)
        dense = transformed.toarray() if hasattr(transformed, "toarray") else transformed
        names = transform.get_feature_names_out()
        class_index = list(classifier.classes_).index(phishing_label)
        try:
            import shap

            shap_values = shap.TreeExplainer(classifier).shap_values(dense, check_additivity=False)
            if isinstance(shap_values, list):
                contributions = shap_values[class_index][0]
            else:
                values = shap_values.values if hasattr(shap_values, "values") else shap_values
                if values.ndim == 3 and values.shape[-1] == len(classifier.classes_):
                    contributions = values[0, :, class_index]
                elif values.ndim == 3 and values.shape[0] == len(classifier.classes_):
                    contributions = values[class_index, 0, :]
                else:
                    contributions = values[0]
            top = sorted(range(len(contributions)), key=lambda index: abs(float(contributions[index])), reverse=True)
            items = []
            for index in top[:8]:
                amount = float(contributions[index])
                if abs(amount) < 0.002:
                    continue
                name = str(names[index]).replace("manual_features__extractor__", "").replace("tfidf__url__", "character pattern: ")
                items.append({"feature": name[:90], "direction": "increases" if amount > 0 else "decreases", "change": round(abs(amount) * 100, 2)})
            return {"status": "available" if items else "no_material_contributors", "method": "shap_tree_explainer", "items": items}
        except Exception:
            logger.info("SHAP TreeExplainer unavailable; using local feature ablation", exc_info=True)
        importances = classifier.feature_importances_
        active = [index for index, value in enumerate(dense[0]) if value != 0 and importances[index] > 0]
        active.sort(key=lambda index: importances[index], reverse=True)
        items = []
        for index in active[:8]:
            altered = dense.copy()
            altered[0, index] = 0
            changed_probability = float(classifier.predict_proba(altered)[0][class_index])
            delta = baseline_probability - changed_probability
            if abs(delta) < 0.002:
                continue
            name = str(names[index]).replace("manual_features__extractor__", "").replace("tfidf__url__", "character pattern: ")
            items.append({"feature": name[:90], "direction": "increases" if delta > 0 else "decreases", "change": round(abs(delta) * 100, 2)})
        return {"status": "available" if items else "no_material_contributors", "method": "model_feature_ablation", "items": items}
    except Exception:
        logger.exception("Local model explanation was unavailable")
        return {"status": "unavailable", "method": None, "items": []}


if __name__ == "__main__":
    from phishing_app.validation import URLValidationError
    try:
        result = predict_url(input("Enter URL: ").strip())
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except URLValidationError as exc:
        print(f"Invalid URL: {exc}")
