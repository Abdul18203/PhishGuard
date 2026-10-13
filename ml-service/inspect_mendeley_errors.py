
import pandas as pd
import joblib
from urllib.parse import urlsplit
from collections import Counter

DATA_FILE = "url_features_extracted1.csv"
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

        from urllib.parse import urlunsplit
        return urlunsplit((
            parts.scheme.lower(),
            netloc,
            parts.path,
            parts.query,
            parts.fragment,
        ))
    except ValueError:
        return value


def url_details(url):
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        return {
            "scheme": parts.scheme.lower() or "(missing)",
            "https": parts.scheme.lower() == "https",
            "hostname": host.lower(),
            "url_length": len(str(url)),
            "has_ip_like_text": any(c.isdigit() for c in host),
            "has_query": bool(parts.query),
            "path_length": len(parts.path),
            "has_at_symbol": "@" in str(url),
        }
    except ValueError:
        return {
            "scheme": "(invalid)",
            "https": False,
            "hostname": "",
            "url_length": len(str(url)),
            "has_ip_like_text": False,
            "has_query": False,
            "path_length": 0,
            "has_at_symbol": "@" in str(url),
        }


print("Loading Mendeley dataset...")
data = pd.read_csv(DATA_FILE)
data = data.dropna(subset=["URL", "ClassLabel"]).copy()
data["ClassLabel"] = data["ClassLabel"].astype(int)

print("Loading existing model...")
model = joblib.load(MODEL_FILE)

urls = data["URL"].astype(str).map(normalize_url)
data["PredictedLabel"] = model.predict(urls)

# Actual 0 = phishing; actual 1 = legitimate.
false_positives = data[
    (data["ClassLabel"] == 1) &
    (data["PredictedLabel"] == 0)
].copy()

false_negatives = data[
    (data["ClassLabel"] == 0) &
    (data["PredictedLabel"] == 1)
].copy()

print("\n===== ERROR COUNTS =====")
print("Legitimate incorrectly flagged as phishing:", len(false_positives))
print("Phishing incorrectly classified as legitimate:", len(false_negatives))


def report_errors(title, errors):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    if errors.empty:
        print("No errors in this category.")
        return

    details = pd.DataFrame(
        errors["URL"].map(url_details).tolist(),
        index=errors.index,
    )

    print("\nScheme counts:")
    print(details["scheme"].value_counts().to_string())

    print("\nHTTPS percentage:",
          round(100 * details["https"].mean(), 2), "%")

    print("Average URL length:",
          round(details["url_length"].mean(), 2))

    print("URLs with query strings:",
          int(details["has_query"].sum()))

    print("URLs containing @:",
          int(details["has_at_symbol"].sum()))

    print("\nMost common hostnames:")
    hosts = details["hostname"]
    for host, count in Counter(hosts).most_common(15):
        print(f"{host or '(missing)'}: {count}")

    print("\nSample URLs (first 15):")
    for url in errors["URL"].head(15):
        print(url)


report_errors(
    "FALSE POSITIVES — legitimate URLs flagged as phishing",
    false_positives,
)

report_errors(
    "FALSE NEGATIVES — phishing URLs missed by the model",
    false_negatives,
)

print("\nInspection complete. The model was not modified.")
