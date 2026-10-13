from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from url_structure_transformer import URLStructureTransformer

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "url_phish_external.csv"
LIVE_MODEL_FILE = BASE_DIR / "phishing_model_normalized.joblib"
COMBINED_MODEL_FILE = BASE_DIR / "phishing_model_combined_experiment.joblib"


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
    for path in (DATA_FILE, LIVE_MODEL_FILE, COMBINED_MODEL_FILE):
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    print("Loading external dataset...")
    data = pd.read_csv(DATA_FILE)

    required = {"url", "label"}
    if not required.issubset(data.columns):
        raise ValueError(
            f"Dataset must contain columns {required}. "
            f"Found: {data.columns.tolist()}"
        )

    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].astype(str).str.strip()
    data = data[data["url"].ne("")].copy()

    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"]).copy()

    if not data["label"].isin([0, 1]).all():
        raise ValueError("Unexpected labels: expected only 0 and 1.")

    data["label"] = data["label"].astype(int)
    data["normalized_url"] = data["url"].map(normalize_url)

    before = len(data)
    data = data.drop_duplicates(
        subset=["normalized_url"],
        keep="first",
    ).reset_index(drop=True)

    print("Rows before deduplication:", before)
    print("Unique normalized URLs:", len(data))
    print("Removed duplicate rows:", before - len(data))
    print("External labels (0=benign, 1=phishing):")
    print(data["label"].value_counts().sort_index().to_string())

    # External: 0=benign, 1=phishing.
    # Models: 0=phishing, 1=legitimate.
    actual = (data["label"] == 0).astype(int)
    urls = data["normalized_url"]

    print("\nLoading existing models...")
    live_model = joblib.load(LIVE_MODEL_FILE)
    combined_model = joblib.load(COMBINED_MODEL_FILE)

    models = [
        ("LIVE MODEL", live_model, urls),
        (
            "COMBINED-FEATURE EXPERIMENT",
            combined_model,
            pd.DataFrame({"url": urls.tolist()}),
        ),
    ]

    for name, model, model_input in models:
        print("\n" + "=" * 65)
        print(name)
        print("=" * 65)

        predictions = model.predict(model_input)
        matrix = confusion_matrix(actual, predictions, labels=[0, 1])

        print(f"Accuracy: {accuracy_score(actual, predictions):.4f}")
        print("Confusion matrix (rows=actual, columns=predicted)")
        print("Rows: phishing, legitimate")
        print("Columns: phishing, legitimate")
        print(matrix)

        print("\nClassification report:")
        print(classification_report(
            actual,
            predictions,
            labels=[0, 1],
            target_names=["Phishing", "Legitimate"],
            digits=4,
            zero_division=0,
        ))

        print("Phishing URLs missed:", int(matrix[0, 1]))
        print("Legitimate URLs falsely flagged:", int(matrix[1, 0]))

    print("\nEvaluation complete. No model was modified.")


if __name__ == "__main__":
    main()