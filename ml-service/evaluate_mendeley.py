
import pandas as pd
import joblib
from urllib.parse import urlsplit, urlunsplit
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# Load the external dataset
data = pd.read_csv("url_features_extracted1.csv")
data = data.dropna(subset=["URL", "ClassLabel"]).copy()
data["ClassLabel"] = data["ClassLabel"].astype(int)

# Load the existing model; do not retrain it
model = joblib.load("phishing_model_normalized.joblib")


def normalize_url(url):
    try:
        parts = urlsplit(str(url).strip())
        hostname = parts.hostname

        if not hostname:
            return str(url).strip()

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
        return str(url).strip()


urls = data["URL"].map(normalize_url)
actual = data["ClassLabel"]
predicted = model.predict(urls)

print("MODEL: phishing_model_normalized.joblib")
print("DATASET: Mendeley LegitPhish")
print("EVALUATED URLS:", len(data))
print("ACCURACY:", round(accuracy_score(actual, predicted), 4))

print("\nCONFUSION MATRIX")
print("Rows = actual [phishing, legitimate]")
print("Columns = predicted [phishing, legitimate]")
print(confusion_matrix(actual, predicted, labels=[0, 1]))

print("\nCLASSIFICATION REPORT")
print(classification_report(
    actual,
    predicted,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    digits=4,
    zero_division=0,
))

print("\nPREDICTION COUNTS")
print(pd.Series(predicted).map({
    0: "Phishing",
    1: "Legitimate"
}).value_counts().to_string())
