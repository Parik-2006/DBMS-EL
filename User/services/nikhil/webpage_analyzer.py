from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urlparse, urljoin
import logging

from User.security import outbound
from User.security.redaction import redact_headers
from User.services.domain_normalization import ensure_scheme, registered_domain_for

logger = logging.getLogger(__name__)

class WebpageAnalyzer:
    """
    Service for safe webpage analysis and evidence collection.
    Produces EVIDENCE ONLY. Does not classify the URL independently.
    Strict safety constraints:
    - Connection timeout (3s) & read timeout (5s)
    - Response size limit (1MB)
    - Maximum 3 redirects
    - Content-Type verification
    - Zero JavaScript execution, zero file downloads execution
    """
    
    MAX_CONTENT_SIZE = 1024 * 1024  # 1MB
    TIMEOUT = (3.0, 5.0)  # (connect timeout, read timeout)
    MAX_REDIRECTS = 3
    TOTAL_TIMEOUT = 15.0  # overall wall-clock budget for the fetch (all hops)
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (Compatible; PhishScan/1.0)"

    # Known suspicious download extensions
    SUSPICIOUS_EXTENSIONS = (
        '.exe', '.scr', '.vbs', '.bat', '.cmd', '.msi', '.ps1', '.jar', '.apk', '.iso', '.dmg'
    )

    # Keywords for defacement detection
    DEFACEMENT_PATTERNS = [
        re.compile(r'\bhacked\s+by\b', re.IGNORECASE),
        re.compile(r'\bdefaced\s+by\b', re.IGNORECASE),
        re.compile(r'\bpwned\s+by\b', re.IGNORECASE),
        re.compile(r'\bgreetz\s+to\b', re.IGNORECASE),
        re.compile(r'\bwe\s+are\s+anonymous\b', re.IGNORECASE),
        re.compile(r'\bsecurity\s+down\b', re.IGNORECASE),
        re.compile(r'\byour\s+system\s+has\s+been\s+hacked\b', re.IGNORECASE)
    ]

    # Keywords for credential harvesting
    CREDENTIAL_HARVESTING_PATTERNS = [
        re.compile(r'\bconfirm\s+(?:your\s+)?password\b', re.IGNORECASE),
        re.compile(r'\bupdate\s+(?:your\s+)?account\s+details\b', re.IGNORECASE),
        re.compile(r'\bverify\s+(?:your\s+)?identity\b', re.IGNORECASE),
        re.compile(r'\baccount\s+suspended\b', re.IGNORECASE),
        re.compile(r'\benter\s+(?:your\s+)?credentials\b', re.IGNORECASE),
        re.compile(r'\blogin\s+to\s+verify\b', re.IGNORECASE),
        re.compile(r'\bunusual\s+sign-in\s+activity\b', re.IGNORECASE),
        re.compile(r'\bbank\s+account\s+verification\b', re.IGNORECASE),
        re.compile(r'\bsecurity\s+alert\b', re.IGNORECASE)
    ]

    @classmethod
    def analyze_webpage(cls, url):
        """
        Fetch and safely analyze a webpage URL.

        Phase 1: the fetch goes through ``User.security.outbound.safe_request``:
        policy-validated, DNS-pinned connection, TLS verified against the
        hostname, each redirect validated independently (max 3), 1 MB cap.
        A policy rejection yields status ``BLOCKED`` (never treated as benign).
        """
        target_url = ensure_scheme(url)
        evidence = cls._initialize_evidence_dict(url, target_url)

        headers = {
            "User-Agent": cls.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            response = outbound.safe_request(
                target_url, method='GET', headers=headers,
                max_bytes=cls.MAX_CONTENT_SIZE, max_redirects=cls.MAX_REDIRECTS,
                connect_timeout=cls.TIMEOUT[0], read_timeout=cls.TIMEOUT[1],
                total_timeout=cls.TOTAL_TIMEOUT,
            )
        except outbound.OutboundBlocked as blocked:
            if blocked.reason == 'too_many_redirects':
                evidence["status"] = "REDIRECT_ERROR"
                evidence["error"] = f"Exceeded maximum redirect limit ({cls.MAX_REDIRECTS})"
                evidence["indicators"].append("SUSPICIOUS_REDIRECT")
            else:
                evidence["status"] = "BLOCKED"
                evidence["security_block"] = blocked.reason
                evidence["error"] = f"Destination blocked by outbound security policy: {blocked.reason}"
            return evidence
        except outbound.OutboundError as err:
            if err.reason == 'timeout' or err.reason == 'dns_timeout':
                evidence["status"] = "TIMEOUT"
                evidence["error"] = "Connection/Read Timeout during webpage fetch"
            elif err.reason == 'tls_error':
                evidence["status"] = "SSL_ERROR"
                evidence["error"] = "SSL Certificate Error during webpage fetch"
            else:
                evidence["status"] = "FAILED"
                evidence["error"] = f"HTTP Request Error: {err.reason}"
            return evidence
        except Exception as e:
            evidence["status"] = "ERROR"
            evidence["error"] = f"Unexpected analysis error: {type(e).__name__}"
            logger.error("Webpage analysis error: %s", type(e).__name__)
            return evidence

        evidence["final_url"] = response.url
        evidence["http_status"] = response.status
        lower_headers = {k.lower(): v for k, v in response.headers.items()}
        evidence["content_type"] = lower_headers.get('content-type', '')
        for sec_header in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
            if sec_header.lower() in lower_headers:
                evidence["security_headers"][sec_header] = lower_headers[sec_header.lower()]
        # Cookies / authorization headers from the target are never persisted.
        evidence["response_headers"] = redact_headers(dict(response.headers))

        if response.history:
            evidence["redirect_chain"] = list(response.history)
            orig_domain = cls._extract_registered_domain(target_url)
            final_domain = cls._extract_registered_domain(response.url)
            if orig_domain and final_domain and orig_domain != final_domain:
                evidence["indicators"].append("SUSPICIOUS_REDIRECT")
                evidence["findings"].append(f"Redirect changed domain from {orig_domain} to {final_domain}")

        content_type_lower = evidence["content_type"].lower()
        if not any(t in content_type_lower for t in ['text/html', 'application/xhtml+xml', 'text/plain']):
            evidence["status"] = "SKIPPED"
            evidence["error"] = f"Unsupported non-HTML content type: {evidence['content_type']}"
            return evidence

        content_length = lower_headers.get('content-length')
        if content_length and content_length.isdigit() and int(content_length) > cls.MAX_CONTENT_SIZE:
            evidence["status"] = "SKIPPED"
            evidence["error"] = f"Content exceeds size limit: {content_length} bytes"
            return evidence

        if response.truncated:
            evidence["findings"].append("Response truncated at 1MB limit")

        encoding = 'utf-8'
        match = re.search(r'charset=([\w.-]+)', content_type_lower)
        if match:
            encoding = match.group(1)
        try:
            html_text = response.body.decode(encoding, errors='replace')
        except LookupError:
            html_text = response.body.decode('utf-8', errors='replace')

        cls._parse_html_content(html_text, evidence, base_url=response.url)
        evidence["status"] = "SUCCESS"
        return evidence

    @classmethod
    def analyze_html_fixture(cls, html_content, base_url="http://example.com"):
        """
        Analyze an HTML string directly for local offline testing and fixtures.
        
        Args:
            html_content: str or bytes HTML markup
            base_url: str simulated base URL
            
        Returns:
            dict: Structured webpage evidence
        """
        if isinstance(html_content, bytes):
            html_content = html_content.decode('utf-8', errors='replace')
            
        evidence = cls._initialize_evidence_dict(base_url, base_url)
        evidence["http_status"] = 200
        evidence["content_type"] = "text/html"
        cls._parse_html_content(html_content, evidence, base_url=base_url)
        evidence["status"] = "SUCCESS"
        return evidence

    @classmethod
    def _initialize_evidence_dict(cls, original_url, target_url):
        return {
            "status": "PENDING",
            "original_url": original_url,
            "final_url": target_url,
            "http_status": None,
            "content_type": "",
            "security_headers": {},
            "response_headers": {},
            "redirect_chain": [],
            "title": "",
            "visible_text": "",
            "metadata": {},
            "forms": [],
            "links": [],
            "iframes": [],
            "script_references": [],
            "hidden_elements": [],
            "suspicious_downloads": [],
            "indicators": [],
            "findings": [],
            "page_structure": {
                "num_tags": 0,
                "num_scripts": 0,
                "num_forms": 0,
                "num_links": 0,
                "num_inputs": 0,
                "num_images": 0
            },
            "security_block": None,
            "error": None,
            "timestamp": time.time()
        }

    @classmethod
    def _parse_html_content(cls, html_text, evidence, base_url):
        """Parse DOM and extract indicators without executing anything"""
        soup = BeautifulSoup(html_text, 'html.parser')
        
        # Structure counts
        tags = soup.find_all()
        evidence["page_structure"]["num_tags"] = len(tags)
        evidence["page_structure"]["num_scripts"] = len(soup.find_all("script"))
        evidence["page_structure"]["num_forms"] = len(soup.find_all("form"))
        evidence["page_structure"]["num_links"] = len(soup.find_all("a"))
        evidence["page_structure"]["num_inputs"] = len(soup.find_all("input"))
        evidence["page_structure"]["num_images"] = len(soup.find_all("img"))

        # Title
        if soup.title and soup.title.string:
            evidence["title"] = soup.title.string.strip()

        # Metadata
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content = meta.get("content")
            if name and content:
                evidence["metadata"][str(name).strip()] = str(content).strip()

        # Hidden elements detection (display:none, visibility:hidden, hidden attribute)
        for el in soup.find_all(attrs={"style": True}):
            style = el.get("style", "").lower()
            if "display:none" in style or "display: none" in style or "visibility:hidden" in style or "visibility: hidden" in style or "opacity:0" in style or "opacity: 0" in style:
                text_content = el.get_text(strip=True)[:100]
                evidence["hidden_elements"].append({
                    "tag": el.name,
                    "snippet": text_content,
                    "style": style
                })
        for el in soup.find_all(attrs={"hidden": True}):
            evidence["hidden_elements"].append({
                "tag": el.name,
                "snippet": el.get_text(strip=True)[:100],
                "attribute": "hidden"
            })
        if evidence["hidden_elements"]:
            evidence["indicators"].append("HIDDEN_CONTENT")
            evidence["findings"].append(f"Found {len(evidence['hidden_elements'])} hidden elements in page")

        # Forms analysis
        base_domain = cls._extract_registered_domain(base_url)
        for form in soup.find_all("form"):
            form_action = form.get("action", "")
            form_method = form.get("method", "GET").upper()
            absolute_action = urljoin(base_url, form_action) if form_action else base_url
            action_domain = cls._extract_registered_domain(absolute_action)

            inputs = []
            has_password = False
            for inp in form.find_all("input"):
                inp_type = inp.get("type", "text").lower()
                inp_name = inp.get("name", "")
                inputs.append({"name": inp_name, "type": inp_type})
                if inp_type == "password":
                    has_password = True

            is_cross_domain = False
            if action_domain and base_domain and action_domain != base_domain:
                is_cross_domain = True

            form_info = {
                "action": form_action,
                "absolute_action": absolute_action,
                "method": form_method,
                "inputs": inputs,
                "has_password": has_password,
                "is_cross_domain": is_cross_domain
            }
            evidence["forms"].append(form_info)

            if has_password:
                if "PASSWORD_FORM" not in evidence["indicators"]:
                    evidence["indicators"].append("PASSWORD_FORM")
                    evidence["findings"].append("Form with password input detected")

            if is_cross_domain:
                if "CROSS_DOMAIN_FORM" not in evidence["indicators"]:
                    evidence["indicators"].append("CROSS_DOMAIN_FORM")
                    evidence["findings"].append(f"Cross-domain form submission detected: target {action_domain} vs host {base_domain}")

        # Links and Suspicious Downloads
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith(('#', 'javascript:')):
                continue
            abs_href = urljoin(base_url, href)
            evidence["links"].append(abs_href)
            
            # Check suspicious downloads
            parsed_href = urlparse(abs_href)
            path_lower = parsed_href.path.lower()
            if any(path_lower.endswith(ext) for ext in cls.SUSPICIOUS_EXTENSIONS):
                evidence["suspicious_downloads"].append(abs_href)
                if "SUSPICIOUS_DOWNLOAD" not in evidence["indicators"]:
                    evidence["indicators"].append("SUSPICIOUS_DOWNLOAD")
                    evidence["findings"].append(f"Suspicious download link detected: {path_lower}")

        # Iframes
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            evidence["iframes"].append(src)
            # Check hidden iframe
            style = iframe.get("style", "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            if width in ['0', '1'] or height in ['0', '1'] or 'display:none' in style or 'visibility:hidden' in style:
                if "SUSPICIOUS_IFRAME" not in evidence["indicators"]:
                    evidence["indicators"].append("SUSPICIOUS_IFRAME")
                    evidence["findings"].append("Hidden zero-size iframe detected")

        # Script References
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                evidence["script_references"].append({"type": "external", "src": src})
            else:
                script_text = script.string or ""
                if "eval(" in script_text or "document.write(unescape(" in script_text or "fromCharCode" in script_text:
                    if "SUSPICIOUS_SCRIPT" not in evidence["indicators"]:
                        evidence["indicators"].append("SUSPICIOUS_SCRIPT")
                        evidence["findings"].append("Obfuscated or eval JavaScript pattern detected")

        # Extract Clean Visible Text
        for el in soup(["script", "style", "noscript", "svg", "header", "footer"]):
            el.decompose()
        raw_text = soup.get_text(separator=' ')
        clean_text = ' '.join(raw_text.split())
        evidence["visible_text"] = clean_text[:5000]

        # Check Defacement keywords in text
        for pat in cls.DEFACEMENT_PATTERNS:
            if pat.search(clean_text):
                if "DEFACEMENT_TEXT" not in evidence["indicators"]:
                    evidence["indicators"].append("DEFACEMENT_TEXT")
                    evidence["findings"].append(f"Defacement indicator keyword detected: '{pat.pattern}'")
                break

        # Check Credential Harvesting keywords in text
        for pat in cls.CREDENTIAL_HARVESTING_PATTERNS:
            if pat.search(clean_text):
                if "CREDENTIAL_HARVESTING_TEXT" not in evidence["indicators"]:
                    evidence["indicators"].append("CREDENTIAL_HARVESTING_TEXT")
                    evidence["findings"].append(f"Credential harvesting keyword detected: '{pat.pattern}'")
                break

    @staticmethod
    def _extract_registered_domain(url_str):
        try:
            return registered_domain_for(url_str)
        except Exception:
            return ""
