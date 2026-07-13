import sqlite3
import json
from datetime import datetime

from config import DATABASE_PATH


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            ml_prediction TEXT NOT NULL,
            risk_score REAL NOT NULL,
            ml_probability REAL NOT NULL,
            domain TEXT,
            is_blacklisted INTEGER,
            domain_age_days INTEGER,
            reasons TEXT NOT NULL,
            features TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan(result):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (
            url,
            prediction,
            ml_prediction,
            risk_score,
            ml_probability,
            domain,
            is_blacklisted,
            domain_age_days,
            reasons,
            features,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["url"],
        result["prediction"],
        result["ml_prediction"],
        result["risk_score"],
        result["ml_phishing_probability"],
        result["blacklist"].get("domain"),
        1 if result["blacklist"].get("is_blacklisted") else 0,
        result["whois"].get("domain_age_days", -1),
        json.dumps(result["reasons"]),
        json.dumps(result["features"]),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_scan_history(limit=100):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            prediction,
            ml_prediction,
            risk_score,
            ml_probability,
            domain,
            is_blacklisted,
            domain_age_days,
            reasons,
            scanned_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    results = []

    for row in rows:
        results.append({
            "id": row[0],
            "url": row[1],
            "prediction": row[2],
            "ml_prediction": row[3],
            "risk_score": row[4],
            "ml_probability": row[5],
            "domain": row[6],
            "is_blacklisted": row[7],
            "domain_age_days": row[8],
            "reasons": row[9],
            "scanned_at": row[10]
        })

    return results


def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE prediction = 'PHISHING'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE prediction = 'LEGITIMATE'")
    legitimate_count = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM scan_history")
    avg_risk = cursor.fetchone()[0]

    cursor.execute("""
        SELECT domain, COUNT(*) as count
        FROM scan_history
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 5
    """)
    top_domains = cursor.fetchall()

    conn.close()

    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "legitimate_count": legitimate_count,
        "avg_risk": round(avg_risk or 0, 2),
        "top_domains": top_domains
    }


def get_scan_by_id(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            prediction,
            ml_prediction,
            risk_score,
            ml_probability,
            domain,
            is_blacklisted,
            domain_age_days,
            reasons,
            features,
            scanned_at
        FROM scan_history
        WHERE id = ?
    """, (scan_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "url": row[1],
        "prediction": row[2],
        "ml_prediction": row[3],
        "risk_score": row[4],
        "ml_probability": row[5],
        "domain": row[6],
        "is_blacklisted": row[7],
        "domain_age_days": row[8],
        "reasons": json.loads(row[9]),
        "features": json.loads(row[10]),
        "scanned_at": row[11]
    }