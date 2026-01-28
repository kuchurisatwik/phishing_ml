import re, math, socket, ssl
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
import tldextract

 
def extract_url_features(url):
    parsed = urlparse(url if re.match(r"^https?://", url) else "https://" + url)
    domain = parsed.netloc
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_repeated_digits": bool(re.search(r"(\d)\1", url)),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", url)),
        "num_hyphens": url.count("-"),
        "num_slashes": url.count("/"),
        "num_underscores": url.count("_"),
        "num_question_marks": url.count("?"),
        "num_equal_signs": url.count("="),
        "num_dollar_signs": url.count("$"),
        "num_exclamations": url.count("!"),
        "num_hashtags": url.count("#"),
        "num_percent": url.count("%"),
        "domain_length": len(domain),
        "num_hyphens_domain": domain.count("-"),
        "has_special_chars_domain": bool(re.search(r"[^a-zA-Z0-9.-]", domain)),
        "num_special_chars_domain": len(re.findall(r"[^a-zA-Z0-9.-]", domain)),
    }

def extract_subdomain_features(url):
    parsed = tldextract.extract(url)
    subdomain = parsed.subdomain
    subdomains = subdomain.split(".") if subdomain else []
    return {
        "num_subdomains": subdomain.count(".") + 1 if subdomain else 0,
        "avg_subdomain_length": float(np.mean([len(s) for s in subdomains])) if subdomains else 0.0,
        "subdomain_length": len(subdomain),
        "subdomain_has_hyphen": "-" in subdomain if subdomain else False,
        "subdomain_has_repeated_digits": bool(re.search(r"(\d)\1", subdomain)) if subdomain else False,
    }

def extract_path_features(url):
    parsed = urlparse(url if re.match(r"^https?://", url) else "https://" + url)
    return {
        "path_length": len(parsed.path),
        "has_query": bool(parsed.query),
        "has_fragment": bool(parsed.fragment),
        "has_anchor": "#" in url
    }


def entropy_of_string(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum([p * math.log2(p) for p in prob if p > 0])

def entropy_features(url):
    parsed = urlparse(url if re.match(r"^https?://", url) else "https://" + url)
    return {
        "entropy_url": entropy_of_string(url),
        "entropy_domain": entropy_of_string(parsed.netloc),
    }


def get_ip_address(url):
    try:
        hostname = urlparse(url if re.match(r"^https?://", url) else "https://" + url).hostname
        if not hostname:
            return None
        return socket.gethostbyname(hostname)
    except:
        return None

def ssl_features(url):
    features = {"ssl_present": 0, "ssl_valid": 0, "ssl_days_to_expiry": -1, "ssl_issuer": None}
    try:
        parsed = urlparse(url if re.match(r"^https?://", url) else "https://" + url)
        hostname = parsed.hostname
        if not hostname:
            return features

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                features["ssl_present"] = 1
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after  = datetime.strptime(cert['notAfter'],  '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()
                features["ssl_valid"] = int(not_before <= now <= not_after)
                features["ssl_days_to_expiry"] = max(0, (not_after - now).days)
                issuer = dict(x[0] for x in cert['issuer'])
                features["ssl_issuer"] = issuer.get("O", issuer.get("organizationName", None))
    except:
        pass
    return features
