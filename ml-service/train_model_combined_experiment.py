
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from collections import Counter
import re
import math

import joblib
import numpy as np
import pandas as pd

from ucimlrepo import fetch_ucirepo
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model_combined_experiment.joblib"


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

        scheme = parts.scheme.lower()
        path = parts.path

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


def extract_features(url):
    """Extract numeric URL structure features without network access."""
    try:
        parts = urlsplit(str(url))
        hostname = (parts.hostname or "").lower()
        path = parts.path or "/"
        query = parts.query
        netloc = parts.netloc
    except ValueError:
        hostname = ""
        path = str(url)
        query = ""
        netloc = ""

    labels = [part for part in hostname.split(".") if part]
    tld = labels[-1] if labels else ""
    domain_without_tld = labels[-2] if len(labels) >= 2 else hostname

    digit_count = sum(ch.isdigit() for ch in str(url))
    special_count = sum(
        ch in "@%=&?_-." for ch in str(url)
    )

    entropy = 0.0
    if url:
        counts = Counter(str(url))
        length = len(str(url))
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    return [
        len(str(url)),
        len(hostname),
        len(path),
        len(query),
        len(labels),
        max(len(labels) - 2, 0),
        len(tld),
        len(domain_without_tld),
        digit_count,
        sum(ch.isalpha() for ch in str(url)),
        sum(ch.isdigit() for ch in str(url)) / max(len(str(url)), 1),
        hostname.count("."),
        hostname.count("-"),
        str(url).count("@"),
        str(url).count("?"),
        str(url).count("="),
        str(url).count("%"),
        str(url).count("//"),
        int(parts.scheme.lower() == "https") if hostname else 0,
        int(parts.scheme.lower() == "http") if hostname else 0,
        int(bool(query)),
        int(bool(re.search(r"\.(exe|bin|zip|rar|7z|scr|bat|msi)(?:$|[?#])",
                           str(url), re.IGNORECASE))),
        entropy,
        len(netloc),
    ]


class URLStructureTransformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.asarray(
            [extract_features(value) for value in X],
            dtype=float,
        )


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

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=42,
    )

    train_idx, test_idx = next(
        splitter.split(urls, labels, groups=hostnames)
    )

    overlap = (
        set(hostnames.iloc[train_idx])
        & set(hostnames.iloc[test_idx])
    )

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

    features = ColumnTransformer(
        transformers=[
            (
                "characters",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=200000,
                    sublinear_tf=True,
                ),
                "url",
            ),
            (
                "structure",
                Pipeline([
                    ("extract", URLStructureTransformer()),
                    ("impute", SimpleImputer(strategy="median")),
                    ("scale", StandardScaler()),
                ]),
                "url",
            ),
        ],
        remainder="drop",
    )

    model = Pipeline([
        ("prepare", features),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    # ColumnTransformer expects a DataFrame with a named "url" column.
    train_frame = pd.DataFrame({"url": X_train})
    test_frame = pd.DataFrame({"url": X_test})

    print("\nTraining combined-feature experiment...")
    model.fit(train_frame, y_train)

    predictions = model.predict(test_frame)

    print("\n--- Hostname-separated evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
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

    print("\n--- Scheme sensitivity checks ---")
    pairs = [
        ("http://github.com/", "https://github.com/"),
        ("http://stackoverflow.com/", "https://stackoverflow.com/"),
        ("http://example.com/", "https://example.com/"),
    ]

    for http_url, https_url in pairs:
        samples = pd.DataFrame({
            "url": [
                normalize_url(http_url),
                normalize_url(https_url),
            ]
        })
        probabilities = model.predict_proba(samples)
        phishing_index = list(model.classes_).index(0)

        print(
            f"{http_url} -> "
            f"{probabilities[0][phishing_index]:.2%} phishing"
        )
        print(
            f"{https_url} -> "
            f"{probabilities[1][phishing_index]:.2%} phishing"
        )

    print("\n--- Known legitimate homepage checks ---")
    for url in [
        "https://stackoverflow.com",
        "https://github.com",
        "https://example.com",
        "https://google.com",
        "https://www.wikipedia.org",
    ]:
        sample = pd.DataFrame({
            "url": [normalize_url(url)]
        })
        probabilities = model.predict_proba(sample)[0]
        phishing_score = float(
            probabilities[list(model.classes_).index(0)]
        )
        prediction = int(model.predict(sample)[0])
        verdict = (
            "PHISHING" if prediction == 0 else "LEGITIMATE"
        )
        print(
            f"{url} -> {verdict} "
            f"({phishing_score:.2%} phishing score)"
        )

    # Save only to a separate experimental filename.
    joblib.dump(model, MODEL_PATH)
    print(f"\nExperimental model saved to: {MODEL_PATH}")
    print("Live model was not modified.")


if __name__ == "__main__":
    main()
