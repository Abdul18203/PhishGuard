from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "url_phish_external.csv"
MODEL_FILE = BASE_DIR / "phishing_model_v2_experiment.joblib"


def normalize_url(value):
    value = str(value).strip()

    try:
        parts = urlsplit(value)
        hostname = parts.hostname

        if not hostname:
            return value

        hostname = hostname.lower().removeprefix("www.")
        netloc = hostname

        if parts.port is not None:
            netloc += f":{parts.port}"

        path = parts.path
        if parts.scheme.lower() in ("http", "https") and not path:
            path = "/"

        return urlunsplit((
            parts.scheme.lower(),
            netloc,
            path,
            parts.query,
            parts.fragment,
        ))
    except ValueError:
        return value


def main():
    for path in (DATA_FILE, MODEL_FILE):
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    print("Loading external dataset...")
    data = pd.read_csv(DATA_FILE)
    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"]).copy()

    if not data["label"].isin([0, 1]).all():
        raise ValueError("Expected external labels 0=benign, 1=phishing.")

    data["label"] = data["label"].astype(int)
    data["normalized_url"] = data["url"].map(normalize_url)
    data = data[data["normalized_url"].ne("")].copy()
    data = data.drop_duplicates("normalized_url").reset_index(drop=True)

    # Convert external labels to PhishGuard convention:
    # external 0=benign, 1=phishing
    # model 0=phishing, 1=legitimate
    actual = (data["label"] == 0).astype(int)
    urls = data["normalized_url"]

    print("Unique normalized URLs:", len(data))
    print("External label counts:")
    print(data["label"].value_counts().sort_index().to_string())

    print("\nLoading V2 experiment...")
    model = joblib.load(MODEL_FILE)
    predictions = model.predict(urls)

    matrix = confusion_matrix(actual, predictions, labels=[0, 1])

    print("\n=== V2 EXTERNAL EVALUATION ===")
    print(f"Accuracy: {accuracy_score(actual, predictions):.4f}")
    print(classification_report(
        actual,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        digits=4,
        zero_division=0,
    ))
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(matrix)
    print("Phishing URLs missed:", int(matrix[0, 1]))
    print("Legitimate URLs falsely flagged:", int(matrix[1, 0]))

    print("\n=== LEGITIMATE HOMEPAGE CHECKS ===")
    for url in [
        "https://example.com/",
        "https://github.com/",
        "https://google.com/",
        "https://www.wikipedia.org/",
    ]:
        normalized = normalize_url(url)
        score = model.predict_proba([normalized])[0][
            list(model.classes_).index(0)
        ]
        prediction = int(model.predict([normalized])[0])
        verdict = "PHISHING" if prediction == 0 else "LEGITIMATE"
        print(f"{url} -> {verdict} ({score:.2%} phishing score)")

    print("\nEvaluation complete. No model was modified.")


if __name__ == "__main__":
    main()