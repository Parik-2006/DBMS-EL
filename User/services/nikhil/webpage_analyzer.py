import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urlparse, urljoin
import tldextract
import logging

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
        
        Args:
            url: str target URL
            
        Returns:
            dict: Structured webpage evidence
        """
        # Ensure scheme
        target_url = url
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        evidence = cls._initialize_evidence_dict(url, target_url)
        
        session = requests.Session()
        session.max_redirects = cls.MAX_REDIRECTS
        
        try:
            headers = {
                "User-Agent": cls.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5"
            }

            response = session.get(
                target_url,
                headers=headers,
                timeout=cls.TIMEOUT,
                allow_redirects=True,
                stream=True
            )

            evidence["final_url"] = response.url
            evidence["http_status"] = response.status_code
            evidence["content_type"] = response.headers.get('Content-Type', '')
            
            # Security headers
            for sec_header in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
                if sec_header in response.headers:
                    evidence["security_headers"][sec_header] = response.headers[sec_header]

            evidence["response_headers"] = dict(response.headers)

            # Redirect chain
            if response.history:
                evidence["redirect_chain"] = [r.url for r in response.history] + [response.url]
                # Check suspicious redirect
                orig_domain = cls._extract_registered_domain(target_url)
                final_domain = cls._extract_registered_domain(response.url)
                if orig_domain and final_domain and orig_domain != final_domain:
                    evidence["indicators"].append("SUSPICIOUS_REDIRECT")
                    evidence["findings"].append(f"Redirect changed domain from {orig_domain} to {final_domain}")

            # Safety check: Content-Type
            content_type_lower = evidence["content_type"].lower()
            if not any(t in content_type_lower for t in ['text/html', 'application/xhtml+xml', 'text/plain']):
                evidence["status"] = "SKIPPED"
                evidence["error"] = f"Unsupported non-HTML content type: {evidence['content_type']}"
                return evidence

            # Safety check: Content-Length header
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > cls.MAX_CONTENT_SIZE:
                evidence["status"] = "SKIPPED"
                evidence["error"] = f"Content exceeds size limit: {content_length} bytes"
                return evidence

            # Safe chunked reading up to 1MB
            raw_bytes = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                raw_bytes.extend(chunk)
                if len(raw_bytes) > cls.MAX_CONTENT_SIZE:
                    evidence["findings"].append("Response truncated at 1MB limit")
                    break

            encoding = response.encoding or 'utf-8'
            try:
                html_text = raw_bytes.decode(encoding, errors='replace')
            except Exception:
                html_text = raw_bytes.decode('utf-8', errors='replace')

            # Analyze the parsed HTML
            cls._parse_html_content(html_text, evidence, base_url=response.url)
            evidence["status"] = "SUCCESS"

        except requests.exceptions.Timeout:
            evidence["status"] = "TIMEOUT"
            evidence["error"] = "Connection/Read Timeout during webpage fetch"
        except requests.exceptions.TooManyRedirects:
            evidence["status"] = "REDIRECT_ERROR"
            evidence["error"] = "Exceeded maximum redirect limit (3)"
            evidence["indicators"].append("SUSPICIOUS_REDIRECT")
        except requests.exceptions.SSLError as ssl_err:
            evidence["status"] = "SSL_ERROR"
            evidence["error"] = f"SSL Certificate Error: {str(ssl_err)}"
        except requests.exceptions.RequestException as req_err:
            evidence["status"] = "FAILED"
            evidence["error"] = f"HTTP Request Error: {str(req_err)}"
        except Exception as e:
            evidence["status"] = "ERROR"
            evidence["error"] = f"Unexpected analysis error: {str(e)}"
            logger.exception("Webpage analysis error")

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
            parsed = urlparse(url_str)
            host = parsed.hostname or url_str
            extracted = tldextract.extract(host)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
            return host.lower()
        except Exception:
            return ""
