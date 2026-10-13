from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "url_phish_external.csv"
MODEL_PATH = BASE_DIR / "phishing_model_v2_experiment.joblib"


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


def get_hostname(value):
    try:
        return (
            urlsplit(str(value)).hostname or ""
        ).lower().removeprefix("www.")
    except ValueError:
        return ""


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    if MODEL_PATH.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing model: {MODEL_PATH}"
        )

    print("Loading local URL-Phish dataset...")
    data = pd.read_csv(DATA_PATH)

    required = {"url", "label"}
    if not required.issubset(data.columns):
        raise ValueError(
            f"Dataset must contain {required}; found {data.columns.tolist()}"
        )

    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"]).copy()

    if not data["label"].isin([0, 1]).all():
        raise ValueError("Expected dataset labels 0=benign and 1=phishing.")

    data["label"] = data["label"].astype(int)
    data["url"] = data["url"].map(normalize_url)
    data = data[data["url"].ne("")].copy()

    # External label 0=benign, 1=phishing.
    # PhishGuard model convention: 0=phishing, 1=legitimate.
    data["target"] = data["label"].map({0: 1, 1: 0})
    data["hostname"] = data["url"].map(get_hostname)
    data = data[data["hostname"].ne("")].copy()

    # Keep a URL only once after normalization.
    data = data.drop_duplicates("url").reset_index(drop=True)

    urls = data["url"]
    targets = data["target"].astype(int)
    hostnames = data["hostname"]

    print("Unique normalized URLs:", len(data))
    print("Target counts (0=phishing, 1=legitimate):")
    print(targets.value_counts().sort_index().to_string())

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=42,
    )
    train_idx, test_idx = next(
        splitter.split(urls, targets, groups=hostnames)
    )

    shared = (
        set(hostnames.iloc[train_idx])
        & set(hostnames.iloc[test_idx])
    )
    if shared:
        raise RuntimeError(
            f"Hostname leakage detected: {len(shared)} shared hostnames"
        )

    X_train = urls.iloc[train_idx]
    X_test = urls.iloc[test_idx]
    y_train = targets.iloc[train_idx]
    y_test = targets.iloc[test_idx]

    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))
    print("Shared hostnames:", len(shared))

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=200000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    print("\nTraining v2 experiment...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])

    print("\n--- Hostname-separated evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        digits=4,
        zero_division=0,
    ))
    print("Confusion matrix (rows=true, columns=predicted):")
    print(matrix)
    print("Phishing URLs missed:", int(matrix[0, 1]))
    print("Legitimate URLs falsely flagged:", int(matrix[1, 0]))

    print("\n--- Known legitimate homepage checks ---")
    for url in [
        "https://example.com/",
        "https://github.com/",
        "https://google.com/",
        "https://www.wikipedia.org/",
    ]:
        normalized = normalize_url(url)
        probabilities = model.predict_proba([normalized])[0]
        phishing_index = list(model.classes_).index(0)
        score = float(probabilities[phishing_index])
        prediction = int(model.predict([normalized])[0])
        verdict = "PHISHING" if prediction == 0 else "LEGITIMATE"
        print(f"{url} -> {verdict} ({score:.2%} phishing score)")

    # Save only under a new experimental filename.
    joblib.dump(model, MODEL_PATH)
    print(f"\nExperiment saved to: {MODEL_PATH}")
    print("The live model was not modified.")


if __name__ == "__main__":
    main()