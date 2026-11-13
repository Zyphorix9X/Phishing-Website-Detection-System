from datetime import datetime, timezone

from predict import predict_url


def analyze_url(url: str, *, rdap_enabled: bool, phishtank_api_key: str, openphish_feed_url: str) -> dict:
    result = predict_url(
        url,
        rdap_enabled=rdap_enabled,
        phishtank_api_key=phishtank_api_key,
        openphish_feed_url=openphish_feed_url,
    )
    result["scanned_at"] = datetime.now(timezone.utc).isoformat()
    return result
