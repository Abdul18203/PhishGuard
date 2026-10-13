
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
from ucimlrepo import fetch_ucirepo
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

# This experiment MUST NOT overwrite the live model.
MODEL_PATH = BASE_DIR / "phishing_model_canonical_experiment.joblib"


def normalize_url(value):
    """Normalize hostnames and canonicalize empty HTTP(S) paths."""
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

        scheme = parts.scheme.lower()
        path = parts.path

        # Experimental change: an empty HTTP(S) path becomes "/".
        if scheme in ("http", "https") and not path:
            path = "/"

        return urlunsplit((
            scheme,
            netloc,
            path,
            parts.query,
            parts.fragment,
        ))

    except ValueError:
        return value


def get_hostname(value):
    try:
        hostname = urlsplit(str(value)).hostname or ""
        return hostname.lower().removeprefix("www.")
    except ValueError:
        return ""


def main():
    print("Loading PhiUSIIL dataset...")
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

    print(f"Usable URLs: {len(urls)}")
    print(f"Unique hostnames: {hostnames.nunique()}")
    print("Assumed labels: 0 = phishing, 1 = legitimate")

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
            f"Hostname leakage detected: {len(overlap)} shared hostnames"
        )

    X_train = urls.iloc[train_idx].map(normalize_url)
    X_test = urls.iloc[test_idx].map(normalize_url)
    y_train = labels.iloc[train_idx]
    y_test = labels.iloc[test_idx]

    print(f"Training records: {len(X_train)}")
    print(f"Testing records: {len(X_test)}")
    print(f"Shared hostnames: {len(overlap)}")

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

    print("\nTraining canonical-URL experiment...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n--- Domain-separated evaluation ---")
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
    print(f"Phishing URLs missed: {matrix[0, 1]}")
    print(f"Legitimate URLs flagged: {matrix[1, 0]}")

    print("\n--- Canonicalization checks ---")

    pairs = [
        ("https://stackoverflow.com",
         "https://stackoverflow.com/"),
        ("https://github.com",
         "https://github.com/"),
        ("https://example.com",
         "https://example.com/"),
    ]

    for first, second in pairs:
        normalized_first = normalize_url(first)
        normalized_second = normalize_url(second)

        score_first = model.predict_proba([normalized_first])[0][
            list(model.classes_).index(0)
        ]
        score_second = model.predict_proba([normalized_second])[0][
            list(model.classes_).index(0)
        ]

        print(f"\n{first}")
        print(f"  Normalized: {normalized_first}")
        print(f"  Phishing score: {score_first:.2%}")

        print(f"{second}")
        print(f"  Normalized: {normalized_second}")
        print(f"  Phishing score: {score_second:.2%}")

        if normalized_first != normalized_second:
            raise RuntimeError(
                "Canonicalization failed for a URL pair."
            )

        if abs(float(score_first) - float(score_second)) > 1e-9:
            raise RuntimeError(
                "Equivalent URLs produced different predictions."
            )

    # Save ONLY to the experimental filename.
    joblib.dump(model, MODEL_PATH)

    print("\nExperimental model saved to:")
    print(MODEL_PATH)
    print("\nLive phishing_model_normalized.joblib was not modified.")


if __name__ == "__main__":
    main()
