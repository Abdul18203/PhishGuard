from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter
import math
import re
import __main__

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "url_phish_external.csv"
MODEL_FILE = BASE_DIR / "phishing_model_combined_experiment.joblib"


def extract_features(url):
    url = str(url)

    try:
        parts = urlsplit(url)
        hostname = (parts.hostname or "").lower()
        path = parts.path or "/"
        query = parts.query
        netloc = parts.netloc
        scheme = parts.scheme.lower()
    except ValueError:
        hostname = ""
        path = url
        query = ""
        netloc = ""
        scheme = ""

    labels = [part for part in hostname.split(".") if part]
    tld = labels[-1] if labels else ""
    domain_without_tld = labels[-2] if len(labels) >= 2 else hostname

    digit_count = sum(ch.isdigit() for ch in url)
    entropy = 0.0

    if url:
        counts = Counter(url)
        length = len(url)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    return [
        len(url),
        len(hostname),
        len(path),
        len(query),
        len(labels),
        max(len(labels) - 2, 0),
        len(tld),
        len(domain_without_tld),
        digit_count,
        sum(ch.isalpha() for ch in url),
        digit_count / max(len(url), 1),
        hostname.count("."),
        hostname.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("%"),
        url.count("//"),
        int(scheme == "https"),
        int(scheme == "http"),
        int(bool(query)),
        int(bool(re.search(
            r"\.(exe|bin|zip|rar|7z|scr|bat|msi)(?:$|[?#])",
            url,
            re.IGNORECASE,
        ))),
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


# The saved experimental model expects this class in __main__.
__main__.URLStructureTransformer = URLStructureTransformer


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")
    if not MODEL_FILE.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_FILE}")

    print("Loading external dataset...")
    data = pd.read_csv(DATA_FILE)
    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"])
    data = data[data["label"].isin([0, 1])].copy()
    data["label"] = data["label"].astype(int)
    data["normalized_url"] = data["url"].map(normalize_url)
    data = data.drop_duplicates("normalized_url").reset_index(drop=True)

    model = joblib.load(MODEL_FILE)
    model_input = pd.DataFrame({"url": data["normalized_url"].tolist()})
    predictions = model.predict(model_input)

    # External labels: 0=benign, 1=phishing.
    data["actual"] = data["label"].map({0: "Legitimate", 1: "Phishing"})
    data["predicted"] = pd.Series(predictions).map({
        0: "Phishing",
        1: "Legitimate",
    }).to_numpy()

    data["hostname"] = data["normalized_url"].map(
        lambda url: (urlsplit(url).hostname or "").lower()
    )
    data["scheme"] = data["normalized_url"].map(
        lambda url: urlsplit(url).scheme.lower() or "(missing)"
    )
    data["tld"] = data["hostname"].map(
        lambda host: host.rsplit(".", 1)[-1] if "." in host else "(none)"
    )
    data["has_path"] = data["normalized_url"].map(
        lambda url: bool(urlsplit(url).path.strip("/"))
    )
    data["has_query"] = data["normalized_url"].map(
        lambda url: bool(urlsplit(url).query)
    )

    false_alarms = data[
        (data["actual"] == "Legitimate")
        & (data["predicted"] == "Phishing")
    ].copy()

    missed_phishing = data[
        (data["actual"] == "Phishing")
        & (data["predicted"] == "Legitimate")
    ].copy()

    print("\n=== OVERALL COUNTS ===")
    print("Rows:", len(data))
    print("Legitimate URLs falsely flagged:", len(false_alarms))
    print("Phishing URLs missed:", len(missed_phishing))

    for column in ["scheme", "tld", "has_path", "has_query"]:
        print(f"\n=== FALSE-ALARM COUNTS BY {column.upper()} ===")
        print(false_alarms[column].value_counts().head(15).to_string())

        print(f"\n=== FALSE-ALARM RATE BY {column.upper()} ===")
        summary = data.groupby(column, dropna=False).apply(
            lambda group: pd.Series({
                "total": len(group),
                "legitimate": int((group["actual"] == "Legitimate").sum()),
                "false_alarms": int((
                    (group["actual"] == "Legitimate")
                    & (group["predicted"] == "Phishing")
                ).sum()),
            }),
            include_groups=False,
        )
        summary["false_alarm_rate_pct"] = (
            100 * summary["false_alarms"]
            / summary["legitimate"].replace(0, np.nan)
        )
        print(
            summary.sort_values("legitimate", ascending=False)
            .head(15)
            .round(2)
            .to_string()
        )

    print("\n=== MOST COMMON LEGITIMATE FALSE-ALARM HOSTNAMES ===")
    print(false_alarms["hostname"].value_counts().head(25).to_string())

    print("\n=== SAMPLE FALSE ALARMS ===")
    print(false_alarms[["url", "hostname"]].head(25).to_string(index=False))

    output = BASE_DIR / "external_false_alarms.csv"
    false_alarms[["url", "hostname", "scheme", "tld"]].to_csv(
        output, index=False
    )
    print(f"\nFalse-alarm details saved to: {output}")


def normalize_url(value):
    from urllib.parse import urlunsplit

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
            parts.scheme.lower(), netloc, path,
            parts.query, parts.fragment,
        ))
    except ValueError:
        return value


if __name__ == "__main__":
    main()