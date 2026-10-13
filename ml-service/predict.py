
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model_normalized.joblib"


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


def main():
    if not MODEL_PATH.exists():
        print("ERROR: Normalized model not found.")
        print("Run: py train_model.py")
        return

    url = input("Enter a URL to check: ").strip()

    if not url:
        print("Please enter a URL.")
        return

    model = joblib.load(MODEL_PATH)
    normalized = normalize_url(url)

    prediction = int(model.predict([normalized])[0])
    probabilities = model.predict_proba([normalized])[0]
    classes = list(model.classes_)

    phishing_probability = float(
        probabilities[classes.index(0)]
    )
    legitimate_probability = float(
        probabilities[classes.index(1)]
    )

    verdict = "PHISHING" if prediction == 0 else "LEGITIMATE"

    print("\n--- PhishGuard ML Prediction ---")
    print(f"URL: {url}")
    print(f"Prediction: {verdict}")
    print(f"Phishing model score: {phishing_probability:.2%}")
    print(f"Legitimate model score: {legitimate_probability:.2%}")
    print("\nA model score is not a guarantee of safety.")


if __name__ == "__main__":
    main()
