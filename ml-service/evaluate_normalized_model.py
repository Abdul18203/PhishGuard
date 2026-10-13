
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
from ucimlrepo import fetch_ucirepo
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model_normalized.joblib"


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

        return urlunsplit((
            parts.scheme.lower(),
            netloc,
            parts.path,
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
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    print("Loading existing normalized model...")
    model = joblib.load(MODEL_PATH)

    print("Downloading evaluation dataset...")
    dataset = fetch_ucirepo(id=967)

    urls = dataset.data.features["URL"].astype(str).str.strip()
    labels = dataset.data.targets["label"].astype(int)

    hostnames = urls.map(get_hostname)

    valid = (
        urls.ne("")
        & hostnames.ne("")
        & labels.isin([0, 1])
    )

    urls = urls[valid].reset_index(drop=True)
    labels = labels[valid].reset_index(drop=True)
    hostnames = hostnames[valid].reset_index(drop=True)

    # Reproduce the fixed, domain-separated split used
    # by the existing training script.
    from sklearn.model_selection import GroupShuffleSplit

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=42,
    )

    train_idx, test_idx = next(
        splitter.split(urls, labels, groups=hostnames)
    )

    train_hosts = set(hostnames.iloc[train_idx])
    test_hosts = set(hostnames.iloc[test_idx])
    overlap = train_hosts & test_hosts

    if overlap:
        raise RuntimeError(
            f"Hostname overlap detected: {len(overlap)}"
        )

    X_test = urls.iloc[test_idx].map(normalize_url)
    y_test = labels.iloc[test_idx]

    print(f"Usable URLs: {len(urls)}")
    print(f"Unique hostnames: {hostnames.nunique()}")
    print(f"Training hostnames: {len(train_hosts)}")
    print(f"Testing URLs: {len(X_test)}")
    print(f"Shared hostnames: {len(overlap)}")

    print("\nEvaluating the existing model...")
    predictions = model.predict(X_test)

    print("\n--- Normalized Model Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")

    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    ))

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )

    print("Confusion matrix (rows=true, columns=predicted):")
    print(matrix)

    print("\n--- Error counts ---")
    print(f"Phishing URLs missed: {matrix[0, 1]}")
    print(f"Legitimate URLs flagged: {matrix[1, 0]}")

    print("\n--- Known legitimate URL checks ---")

    for url in [
        "https://example.com",
        "https://github.com",
        "https://google.com",
        "https://www.google.com",
        "https://www.wikipedia.org",
    ]:
        normalized = normalize_url(url)
        prediction = int(model.predict([normalized])[0])
        probabilities = model.predict_proba([normalized])[0]
        classes = list(model.classes_)

        phishing_score = float(
            probabilities[classes.index(0)]
        )

        verdict = (
            "PHISHING" if prediction == 0
            else "LEGITIMATE"
        )

        print(
            f"{url} -> {verdict} "
            f"({phishing_score:.2%} phishing score)"
        )

    print("\nEvaluation completed.")
    print("Existing model was not modified.")


if __name__ == "__main__":
    main()
