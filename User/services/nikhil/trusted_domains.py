"""
Trusted Domain Service — Legitimate Domain Intelligence.
Provides supporting evidence only. Does NOT automatically classify URLs as Benign.
"""
import re
import math
import logging
from urllib.parse import urlparse
from collections import Counter

logger = logging.getLogger(__name__)


# Curated list of well-known legitimate domains with categories
# IMPORTANT: Presence here is SUPPORTING EVIDENCE, not a final classification.
TRUSTED_DOMAINS = {
    # Education
    "nptel.ac.in": {"category": "education", "org": "NPTEL/IIT", "verified": True},
    "onlinecourses.nptel.ac.in": {"category": "education", "org": "NPTEL", "verified": True},
    "swayam.gov.in": {"category": "education", "org": "SWAYAM/Govt India", "verified": True},
    "coursera.org": {"category": "education", "org": "Coursera", "verified": True},
    "edx.org": {"category": "education", "org": "edX", "verified": True},
    "khanacademy.org": {"category": "education", "org": "Khan Academy", "verified": True},
    "mit.edu": {"category": "university", "org": "MIT", "verified": True},
    "stanford.edu": {"category": "university", "org": "Stanford", "verified": True},
    "harvard.edu": {"category": "university", "org": "Harvard", "verified": True},

    # Government
    "gov.in": {"category": "government", "org": "Indian Government", "verified": True},
    "nic.in": {"category": "government", "org": "NIC India", "verified": True},
    "gov.uk": {"category": "government", "org": "UK Government", "verified": True},
    "usa.gov": {"category": "government", "org": "US Government", "verified": True},

    # Technology
    "google.com": {"category": "technology", "org": "Google", "verified": True},
    "microsoft.com": {"category": "technology", "org": "Microsoft", "verified": True},
    "apple.com": {"category": "technology", "org": "Apple", "verified": True},
    "mozilla.org": {"category": "technology", "org": "Mozilla", "verified": True},

    # Developer
    "github.com": {"category": "developer", "org": "GitHub", "verified": True},
    "gitlab.com": {"category": "developer", "org": "GitLab", "verified": True},
    "stackoverflow.com": {"category": "developer", "org": "Stack Overflow", "verified": True},
    "npmjs.com": {"category": "developer", "org": "npm", "verified": True},
    "pypi.org": {"category": "developer", "org": "PyPI", "verified": True},

    # Cloud
    "amazonaws.com": {"category": "cloud", "org": "AWS", "verified": True},
    "azure.com": {"category": "cloud", "org": "Microsoft Azure", "verified": True},
    "cloud.google.com": {"category": "cloud", "org": "Google Cloud", "verified": True},

    # Search
    "google.co.in": {"category": "search", "org": "Google India", "verified": True},
    "bing.com": {"category": "search", "org": "Bing", "verified": True},

    # AI / Chat
    "chatgpt.com": {"category": "technology", "org": "OpenAI", "verified": True},
    "openai.com": {"category": "technology", "org": "OpenAI", "verified": True},

    # Documentation
    "docs.python.org": {"category": "documentation", "org": "Python", "verified": True},
    "developer.mozilla.org": {"category": "documentation", "org": "MDN", "verified": True},
    "docs.djangoproject.com": {"category": "documentation", "org": "Django", "verified": True},

    # News
    "bbc.com": {"category": "news", "org": "BBC", "verified": True},
    "reuters.com": {"category": "news", "org": "Reuters", "verified": True},

    # Banking (examples)
    "sbi.co.in": {"category": "banking", "org": "SBI", "verified": True},
    "onlinesbi.sbi": {"category": "banking", "org": "SBI Online", "verified": True},

    # Commerce
    "amazon.in": {"category": "commerce", "org": "Amazon India", "verified": True},
    "amazon.com": {"category": "commerce", "org": "Amazon", "verified": True},
    "flipkart.com": {"category": "commerce", "org": "Flipkart", "verified": True},

    # Social
    "wikipedia.org": {"category": "education", "org": "Wikipedia", "verified": True},
    "linkedin.com": {"category": "technology", "org": "LinkedIn", "verified": True},
    "youtube.com": {"category": "technology", "org": "YouTube", "verified": True},
}

# Trusted TLDs that are harder to register (supporting evidence)
TRUSTED_TLDS = {
    ".edu", ".gov", ".mil", ".ac.in", ".edu.in", ".gov.in",
    ".ac.uk", ".gov.uk", ".edu.au", ".gov.au"
}

# Suspicious tokens commonly found in phishing/malware URLs
SUSPICIOUS_URL_TOKENS = {
    "login", "signin", "verify", "update", "secure", "account",
    "confirm", "banking", "password", "credential", "suspended",
    "alert", "unusual", "paypal", "wallet", "reward", "prize",
    "winner", "free-gift", "urgent", "limited-time", "click-here",
    "download-now", "install", "update-required"
}

# Suspicious ports (not standard HTTP/HTTPS)
SUSPICIOUS_PORTS = {8080, 8443, 4443, 9090, 3000, 5000, 7777, 6666}


class TrustedDomainService:
    """
    Provides legitimate domain intelligence and URL feature extraction.
    Returns EVIDENCE — never a final classification.
    """

    @classmethod
    def lookup_domain(cls, url):
        """
        Look up domain in trusted domain intelligence.

        Returns:
            dict: {
                "is_known": bool,
                "domain": str,
                "registered_domain": str,
                "category": str or None,
                "organization": str or None,
                "trusted_tld": bool,
                "evidence_type": "TRUSTED_DOMAIN"|"TRUSTED_TLD"|"UNKNOWN"
            }
        """
        try:
            import tldextract

            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
            hostname = (parsed.hostname or "").lower()
            ext = tldextract.extract(hostname)
            registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else hostname

            result = {
                "is_known": False,
                "domain": hostname,
                "registered_domain": registered_domain,
                "category": None,
                "organization": None,
                "trusted_tld": False,
                "evidence_type": "UNKNOWN"
            }

            # Check exact hostname match
            if hostname in TRUSTED_DOMAINS:
                info = TRUSTED_DOMAINS[hostname]
                result.update({
                    "is_known": True,
                    "category": info["category"],
                    "organization": info["org"],
                    "evidence_type": "TRUSTED_DOMAIN"
                })
                return result

            # Check registered domain match
            if registered_domain in TRUSTED_DOMAINS:
                info = TRUSTED_DOMAINS[registered_domain]
                result.update({
                    "is_known": True,
                    "category": info["category"],
                    "organization": info["org"],
                    "evidence_type": "TRUSTED_DOMAIN"
                })
                return result

            # Check if hostname is a subdomain of a trusted domain
            for trusted, info in TRUSTED_DOMAINS.items():
                if hostname.endswith(f".{trusted}"):
                    result.update({
                        "is_known": True,
                        "category": info["category"],
                        "organization": info["org"],
                        "evidence_type": "TRUSTED_DOMAIN"
                    })
                    return result

            # Check trusted TLDs
            suffix = f".{ext.suffix}" if ext.suffix else ""
            for ttld in TRUSTED_TLDS:
                if suffix.endswith(ttld) or hostname.endswith(ttld):
                    result["trusted_tld"] = True
                    result["evidence_type"] = "TRUSTED_TLD"
                    break

            return result

        except Exception as e:
            logger.warning(f"Domain lookup error: {e}")
            return {
                "is_known": False, "domain": "", "registered_domain": "",
                "category": None, "organization": None,
                "trusted_tld": False, "evidence_type": "ERROR"
            }

    @classmethod
    def extract_url_features(cls, url):
        """
        Extract deterministic URL/domain features for legitimacy assessment.

        Returns:
            dict of extracted features
        """
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
            fragment = parsed.fragment or ""

            # Basic length features
            url_length = len(url)
            hostname_length = len(hostname)

            # Subdomain depth
            parts = hostname.split(".")
            subdomain_depth = max(0, len(parts) - 2)

            # Path depth
            path_parts = [p for p in path.split("/") if p]
            path_depth = len(path_parts)

            # Query parameters
            query_count = len([q for q in query.split("&") if q and "=" in q]) if query else 0
            has_fragment = bool(fragment)

            # IP hostname detection
            is_ip = False
            try:
                import socket
                socket.inet_aton(hostname)
                is_ip = True
            except (socket.error, OSError):
                pass

            # Punycode detection (IDN)
            has_punycode = "xn--" in hostname.lower()

            # Unusual TLD indicators
            unusual_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".buzz"}
            import tldextract
            ext = tldextract.extract(hostname)
            tld = f".{ext.suffix}" if ext.suffix else ""
            unusual_tld = tld.lower() in unusual_tlds

            # Entropy calculations
            hostname_entropy = cls._calculate_entropy(hostname)
            path_entropy = cls._calculate_entropy(path)

            # Character ratios
            digit_ratio = sum(c.isdigit() for c in hostname) / max(1, len(hostname))
            hyphen_ratio = hostname.count("-") / max(1, len(hostname))

            # Suspicious token detection
            url_lower = url.lower()
            found_suspicious_tokens = [t for t in SUSPICIOUS_URL_TOKENS if t in url_lower]

            # Credential-themed path indicators
            credential_paths = ["login", "signin", "auth", "verify", "account", "password", "banking"]
            path_lower = path.lower()
            credential_path = any(cp in path_lower for cp in credential_paths)

            # Port detection
            port = parsed.port
            suspicious_port = port in SUSPICIOUS_PORTS if port else False

            # Encoded characters
            encoded_chars = url.count("%")

            # Excessive separators
            excessive_hyphens = hostname.count("-") >= 3
            excessive_dots = hostname.count(".") >= 5

            return {
                "url_length": url_length,
                "hostname_length": hostname_length,
                "subdomain_depth": subdomain_depth,
                "path_depth": path_depth,
                "query_count": query_count,
                "has_fragment": has_fragment,
                "is_ip_hostname": is_ip,
                "has_punycode": has_punycode,
                "unusual_tld": unusual_tld,
                "hostname_entropy": round(hostname_entropy, 3),
                "path_entropy": round(path_entropy, 3),
                "digit_ratio": round(digit_ratio, 3),
                "hyphen_ratio": round(hyphen_ratio, 3),
                "suspicious_tokens": found_suspicious_tokens,
                "suspicious_token_count": len(found_suspicious_tokens),
                "credential_path": credential_path,
                "suspicious_port": suspicious_port,
                "encoded_chars": encoded_chars,
                "excessive_hyphens": excessive_hyphens,
                "excessive_dots": excessive_dots,
                "tld": tld
            }

        except Exception as e:
            logger.warning(f"URL feature extraction error: {e}")
            return {"error": str(e)}

    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
