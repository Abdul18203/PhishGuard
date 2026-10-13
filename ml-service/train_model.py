
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
from ucimlrepo import fetch_ucirepo
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model_normalized.joblib"


def normalize_url(value):
    """Normalize hostname capitalization and remove a leading www."""
    value = str(value).strip()

    try:
        parts = urlsplit(value)
        hostname = parts.hostname

        if not hostname:
            return value

        hostname = hostname.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]

        # Preserve credentials, port, path, query and fragment.
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
        return (urlsplit(str(value)).hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


print("Downloading the dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].astype(str).str.strip()
labels = dataset.data.targets["label"].astype(int)
hostnames = urls.map(get_hostname)

valid = urls.ne("") & hostnames.ne("") & labels.isin([0, 1])
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)
hostnames = hostnames[valid].reset_index(drop=True)

# Group by original hostname so one domain cannot appear in both splits.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.2,
    random_state=42,
)
train_idx, test_idx = next(
    splitter.split(urls, labels, groups=hostnames)
)

X_train = urls.iloc[train_idx].map(normalize_url)
X_test = urls.iloc[test_idx].map(normalize_url)
y_train = labels.iloc[train_idx]
y_test = labels.iloc[test_idx]

print(f"Training records: {len(X_train)}")
print(f"Testing records: {len(X_test)}")
print(
    "Shared hostnames:",
    len(set(hostnames.iloc[train_idx]) & set(hostnames.iloc[test_idx]))
)

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

print("Training normalized-URL experiment...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n--- Domain-separated evaluation ---")
print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    )
)

print("\n--- Known legitimate URL checks ---")
for url in [
    "https://example.com",
    "https://www.example.com",
    "https://github.com",
    "https://www.github.com",
    "https://google.com",
    "https://www.google.com",
    "https://www.wikipedia.org",
]:
    normalized = normalize_url(url)
    prediction = int(model.predict([normalized])[0])
    probability = model.predict_proba([normalized])[0][
        list(model.classes_).index(0)
    ]
    verdict = "PHISHING" if prediction == 0 else "LEGITIMATE"
    print(f"{url} -> {verdict} ({probability:.2%} phishing score)")

joblib.dump(model, MODEL_PATH)
print(f"\nExperimental model saved to: {MODEL_PATH}")
print("Original phishing_model.joblib remains unchanged.")
