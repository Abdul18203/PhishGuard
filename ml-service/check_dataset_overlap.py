
import pandas as pd
from urllib.parse import urlsplit
from ucimlrepo import fetch_ucirepo

MENDELEY_FILE = "url_features_extracted1.csv"


def normalize_url(url):
    try:
        parts = urlsplit(str(url).strip())
        hostname = (parts.hostname or "").lower().removeprefix("www.")

        if not hostname:
            return str(url).strip()

        netloc = hostname
        if parts.port is not None:
            netloc += f":{parts.port}"

        return parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment
    except ValueError:
        return str(url).strip()


def get_hostname(url):
    try:
        return (urlsplit(str(url).strip()).hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


print("Loading Mendeley dataset...")
mendeley = pd.read_csv(MENDELEY_FILE)
mendeley = mendeley.dropna(subset=["URL", "ClassLabel"]).copy()
mendeley["ClassLabel"] = mendeley["ClassLabel"].astype(int)
mendeley["normalized_url"] = mendeley["URL"].map(normalize_url)
mendeley["hostname"] = mendeley["URL"].map(get_hostname)

print("Fetching PhiUSIIL from UCI...")
dataset = fetch_ucirepo(id=967)
phi = dataset.data.features["URL"].dropna().astype(str).str.strip()

phi_urls = {normalize_url(url) for url in phi}
phi_hosts = {get_hostname(url) for url in phi} - {""}

mendeley["exact_match"] = mendeley["normalized_url"].map(
    lambda url: url in phi_urls
)
mendeley["host_match"] = mendeley["hostname"].map(
    lambda host: bool(host) and host in phi_hosts
)

exact_unseen = mendeley[~mendeley["exact_match"]]
host_unseen = mendeley[~mendeley["host_match"]]

print("\n===== OVERLAP SUMMARY =====")
print("Mendeley labeled rows:", len(mendeley))
print("Exact URL matches in PhiUSIIL:", int(mendeley["exact_match"].sum()))
print("Rows without exact URL match:", len(exact_unseen))
print("Rows with hostname in PhiUSIIL:", int(mendeley["host_match"].sum()))
print("Rows with hostname absent from PhiUSIIL:", len(host_unseen))

print("\n===== LABEL COUNTS IN STRICTER SUBSETS =====")
print("\nURLs without exact match:")
print(exact_unseen["ClassLabel"].value_counts().sort_index().to_string())

print("\nURLs whose hostname is absent:")
print(host_unseen["ClassLabel"].value_counts().sort_index().to_string())

print("\n===== UNIQUE HOSTNAME COUNTS =====")
print("Unique hostnames absent from PhiUSIIL:",
      host_unseen["hostname"].nunique())

print("\nThis script only analyzes dataset overlap.")
print("It does not load, retrain, or modify the live model.")
