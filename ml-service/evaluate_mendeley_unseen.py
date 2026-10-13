
import pandas as pd
import joblib

from urllib.parse import urlsplit, urlunsplit
from ucimlrepo import fetch_ucirepo
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

MENDELEY_FILE = "url_features_extracted1.csv"
MODEL_FILE = "phishing_model_normalized.joblib"


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


def get_hostname(url):
    try:
        return (
            urlsplit(str(url).strip()).hostname or ""
        ).lower().removeprefix("www.")
    except ValueError:
        return ""


def evaluate_subset(name, subset, model):
    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    if subset.empty:
        print("No records available.")
        return

    actual = subset["ClassLabel"].astype(int)
    urls = subset["URL"].map(normalize_url)
    predicted = model.predict(urls)

    print("Records:", len(subset))
    print("Actual label counts:")
    print(actual.value_counts().sort_index().to_string())

    print("\nAccuracy:", round(accuracy_score(actual, predicted), 4))

    print("\nConfusion matrix")
    print("Rows = actual [phishing, legitimate]")
    print("Columns = predicted [phishing, legitimate]")
    print(confusion_matrix(actual, predicted, labels=[0, 1]))

    print("\nClassification report")
    print(classification_report(
        actual,
        predicted,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        digits=4,
        zero_division=0,
    ))


print("Loading Mendeley dataset...")
data = pd.read_csv(MENDELEY_FILE)
data = data.dropna(subset=["URL", "ClassLabel"]).copy()
data["ClassLabel"] = data["ClassLabel"].astype(int)
data["hostname"] = data["URL"].map(get_hostname)

print("Fetching PhiUSIIL from UCI...")
dataset = fetch_ucirepo(id=967)

phi_urls = (
    dataset.data.features["URL"]
    .dropna()
    .astype(str)
    .map(normalize_url)
)

phi_hosts = {
    get_hostname(url)
    for url in dataset.data.features["URL"].dropna()
} - {""}

phi_url_set = set(phi_urls)

data["normalized_url"] = data["URL"].map(normalize_url)

exact_unseen = data[
    ~data["normalized_url"].isin(phi_url_set)
].copy()

hostname_unseen = data[
    ~data["hostname"].isin(phi_hosts)
    & data["hostname"].ne("")
].copy()

print("Loading existing model...")
model = joblib.load(MODEL_FILE)

evaluate_subset(
    "Mendeley URLs absent from PhiUSIIL by normalized URL",
    exact_unseen,
    model,
)

evaluate_subset(
    "Mendeley URLs from hostnames absent from PhiUSIIL",
    hostname_unseen,
    model,
)

print("\nEvaluation complete.")
print("The live model was not retrained or modified.")
