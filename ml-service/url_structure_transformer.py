
from collections import Counter
from urllib.parse import urlsplit
import math
import re

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


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
