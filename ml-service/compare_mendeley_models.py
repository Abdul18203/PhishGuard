
import pandas as pd
import joblib

from urllib.parse import urlsplit, urlunsplit
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

from url_structure_transformer import URLStructureTransformer

DATA_FILE = "url_features_extracted1.csv"
LIVE_MODEL_FILE = "phishing_model_normalized.joblib"
COMBINED_MODEL_FILE = "phishing_model_combined_experiment.joblib"


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


def evaluate_model(name, model, urls, actual, combined=False):
    print("\n" + "=" * 65)
    print(name)
    print("=" * 65)

    # The combined pipeline expects a DataFrame with a "url" column.
    model_input = (
        pd.DataFrame({"url": urls.tolist()})
        if combined
        else urls
    )

    predicted = model.predict(model_input)

    print("Accuracy:", round(accuracy_score(actual, predicted), 4))

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

    return predicted


print("Loading Mendeley dataset...")
data = pd.read_csv(DATA_FILE)
data = data.dropna(subset=["URL", "ClassLabel"]).copy()
data["ClassLabel"] = data["ClassLabel"].astype(int)

urls = data["URL"].map(normalize_url)
actual = data["ClassLabel"]

print("Labeled URLs:", len(data))

print("Loading live model...")
live_model = joblib.load(LIVE_MODEL_FILE)

print("Loading combined-feature experiment...")
combined_model = joblib.load(COMBINED_MODEL_FILE)

live_predictions = evaluate_model(
    "LIVE MODEL",
    live_model,
    urls,
    actual,
)

combined_predictions = evaluate_model(
    "COMBINED-FEATURE EXPERIMENT",
    combined_model,
    urls,
    actual,
    combined=True,
)

print("\n" + "=" * 65)
print("DIRECT COMPARISON")
print("=" * 65)

print(
    "Live model accuracy:",
    f"{accuracy_score(actual, live_predictions):.4f}",
)
print(
    "Combined model accuracy:",
    f"{accuracy_score(actual, combined_predictions):.4f}",
)

print(
    "Live phishing missed:",
    int(((actual == 0) & (live_predictions == 1)).sum()),
)
print(
    "Combined phishing missed:",
    int(((actual == 0) & (combined_predictions == 1)).sum()),
)

print(
    "Live legitimate false alarms:",
    int(((actual == 1) & (live_predictions == 0)).sum()),
)
print(
    "Combined legitimate false alarms:",
    int(((actual == 1) & (combined_predictions == 0)).sum()),
)

print("\nComparison complete. No model was modified.")
