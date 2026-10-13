
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

CHAR_MODEL_PATH = BASE_DIR / "phishing_model_char_experiment.joblib"
WORD_MODEL_PATH = BASE_DIR / "phishing_model_word_experiment.joblib"


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


def build_model(vectorizer):
    return Pipeline([
        ("tfidf", vectorizer),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )),
    ])


def evaluate_model(name, model, X_test, y_test):
    predictions = model.predict(X_test)

    print(f"\n{'=' * 65}")
    print(name)
    print("=" * 65)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")

    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    ))

    print("Confusion matrix (rows=true, columns=predicted):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    print("\nKnown legitimate URL checks:")

    test_urls = [
        "https://example.com/",
        "https://github.com/",
        "https://google.com/",
        "https://www.google.com/",
        "https://www.wikipedia.org/",
        "https://stackoverflow.com/questions/tagged/php",
    ]

    for url in test_urls:
        normalized = normalize_url(url)
        prediction = int(model.predict([normalized])[0])
        probabilities = model.predict_proba([normalized])[0]
        phishing_score = float(
            probabilities[list(model.classes_).index(0)]
        )

        verdict = (
            "PHISHING" if prediction == 0 else "LEGITIMATE"
        )

        print(
            f"{url} -> {verdict} "
            f"(phishing score: {phishing_score:.2%})"
        )


print("Loading PhiUSIIL dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].astype(str).str.strip()
labels = dataset.data.targets["label"].astype(int)
hostnames = urls.map(get_hostname)

valid = urls.ne("") & hostnames.ne("") & labels.isin([0, 1])

urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)
hostnames = hostnames[valid].reset_index(drop=True)

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

shared_hostnames = (
    set(hostnames.iloc[train_idx])
    & set(hostnames.iloc[test_idx])
)

print(f"Training records: {len(X_train)}")
print(f"Testing records: {len(X_test)}")
print(f"Shared hostnames: {len(shared_hostnames)}")

# Model A: character-level n-grams.
char_model = build_model(TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=200000,
    sublinear_tf=True,
))

# Model B: word/token-level n-grams suited to URL components.
word_model = build_model(TfidfVectorizer(
    analyzer="word",
    token_pattern=r"(?u)[A-Za-z0-9.-]+",
    ngram_range=(1, 3),
    min_df=2,
    max_features=100000,
    sublinear_tf=True,
    lowercase=True,
))

print("\nTraining character-level model...")
char_model.fit(X_train, y_train)

evaluate_model(
    "CHARACTER-LEVEL MODEL",
    char_model,
    X_test,
    y_test,
)

print("\nSaving character-level experimental model...")
joblib.dump(char_model, CHAR_MODEL_PATH)
print(f"Saved: {CHAR_MODEL_PATH}")

print("\nTraining word-level model...")
word_model.fit(X_train, y_train)

evaluate_model(
    "WORD-LEVEL MODEL",
    word_model,
    X_test,
    y_test,
)

print("\nSaving word-level experimental model...")
joblib.dump(word_model, WORD_MODEL_PATH)
print(f"Saved: {WORD_MODEL_PATH}")

print("\n" + "=" * 65)
print("EXPERIMENT COMPLETE")
print("=" * 65)
print("Live model was not modified.")
print("Existing backup was not modified.")
print("Both experimental models were saved separately.")
