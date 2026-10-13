
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
from flask import Flask, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model_normalized.joblib"

app = Flask(__name__)


def normalize_url(value):
    value = value.strip()

    try:
        parts = urlsplit(value)
        hostname = parts.hostname

        if not hostname:
            return value

        hostname = hostname.lower().removeprefix("www.")
        netloc = hostname

        if parts.port is not None:
            netloc += f":{parts.port}"

        return urlunsplit((
            parts.scheme.lower(),
            netloc,
            parts.path,
            parts.query,
            parts.fragment,
        ))
    except ValueError:
        return value


model = joblib.load(MODEL_PATH)


@app.get("/health")
def health():
    return jsonify({
        "status": "UP",
        "service": "PhishGuard ML Service"
    })


@app.post("/predict")
def predict():
    body = request.get_json(silent=True) or {}
    url = body.get("url")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"message": "A URL is required."}), 400

    url = url.strip()

    try:
        parts = urlsplit(url)

        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return jsonify({
                "message": "Enter a valid HTTP or HTTPS URL."
            }), 400

        # Accessing port also catches malformed port values.
        _ = parts.port

    except ValueError:
        return jsonify({"message": "The URL is malformed."}), 400

    normalized = normalize_url(url)
    prediction = int(model.predict([normalized])[0])
    probabilities = model.predict_proba([normalized])[0]
    classes = list(model.classes_)

    phishing_score = float(probabilities[classes.index(0)])
    legitimate_score = float(probabilities[classes.index(1)])

    return jsonify({
        "url": url,
        "prediction": "PHISHING" if prediction == 0 else "LEGITIMATE",
        "phishingScore": round(phishing_score, 4),
        "legitimateScore": round(legitimate_score, 4),
        "model": "TF-IDF + Logistic Regression"
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
