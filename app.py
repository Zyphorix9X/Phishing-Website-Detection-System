import logging
import os

from flask import Flask, render_template, request, jsonify, send_file

from predict import predict_url
from database import (
    init_db,
    save_scan,
    get_scan_history,
    get_dashboard_stats,
    get_scan_by_id
)
from report_generator import generate_pdf_report
from config import LOG_FILE_PATH, METRICS_PATH, CONFUSION_MATRIX_PATH


app = Flask(__name__)

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("result.html", error="Please enter a valid URL.")

    try:
        result = predict_url(url)
        save_scan(result)

        logging.info(
            "URL=%s Prediction=%s Risk=%s",
            result["url"],
            result["prediction"],
            result["risk_score"]
        )

        return render_template("result.html", result=result)

    except FileNotFoundError:
        return render_template(
            "result.html",
            error="Model file not found. Please run python train_model.py first."
        )

    except Exception as e:
        return render_template(
            "result.html",
            error=f"Unexpected error: {str(e)}"
        )


@app.route("/history")
def history():
    scans = get_scan_history()
    return render_template("history.html", scans=scans)


@app.route("/admin")
def admin():
    stats = get_dashboard_stats()

    metrics = None
    if os.path.exists(METRICS_PATH):
        import json
        with open(METRICS_PATH, "r", encoding="utf-8") as file:
            metrics = json.load(file)

    confusion_matrix_exists = os.path.exists(CONFUSION_MATRIX_PATH)

    return render_template(
        "admin.html",
        stats=stats,
        metrics=metrics,
        confusion_matrix_exists=confusion_matrix_exists
    )


@app.route("/models/confusion-matrix")
def confusion_matrix_image():
    if not os.path.exists(CONFUSION_MATRIX_PATH):
        return "Confusion matrix not found. Train the model first.", 404

    return send_file(CONFUSION_MATRIX_PATH, mimetype="image/png")


@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    scan = get_scan_by_id(scan_id)

    if not scan:
        return "Scan not found", 404

    filepath = generate_pdf_report(scan)

    return send_file(filepath, as_attachment=True)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = data["url"].strip()

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    result = predict_url(url)
    save_scan(result)

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(get_scan_history())


if __name__ == "__main__":
    app.run(debug=True)