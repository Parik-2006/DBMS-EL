import requests
from bs4 import BeautifulSoup
import re
import time

class WebpageAnalyzer:
    """Service for safe webpage analysis and evidence collection"""
    
    MAX_CONTENT_SIZE = 1024 * 1024  # 1MB
    TIMEOUT = (5, 10)  # (connect, read)
    MAX_REDIRECTS = 3
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    @staticmethod
    def analyze_webpage(url):
        """
        Fetch and analyze webpage content safely
        
        Returns:
            dict: Webpage evidence
        """
        evidence = {
            "status": "PENDING",
            "url": url,
            "title": "",
            "text": "",
            "html_summary": "",
            "metadata": {},
            "forms": [],
            "suspicious_elements": [],
            "javascript_indicators": [],
            "redirects": [],
            "content_type": "",
            "response_headers": {},
            "error": None,
            "timestamp": time.time()
        }
        
        try:
            headers = {"User-Agent": WebpageAnalyzer.USER_AGENT}
            
            # Use stream=True to check content size before downloading
            response = requests.get(
                url, 
                headers=headers, 
                timeout=WebpageAnalyzer.TIMEOUT, 
                allow_redirects=True,
                stream=True
            )
            
            evidence["content_type"] = response.headers.get('Content-Type', '')
            evidence["response_headers"] = dict(response.headers)
            
            # Record redirect history
            if response.history:
                evidence["redirects"] = [r.url for r in response.history]
            
            # Safety check: Content-Type
            if 'text/html' not in evidence["content_type"].lower():
                evidence["status"] = "SKIPPED"
                evidence["error"] = f"Unsupported content type: {evidence['content_type']}"
                return evidence

            # Safety check: Content-Length
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > WebpageAnalyzer.MAX_CONTENT_SIZE:
                evidence["status"] = "SKIPPED"
                evidence["error"] = "Content too large"
                return evidence

            # Read content with limit
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > WebpageAnalyzer.MAX_CONTENT_SIZE:
                    evidence["error"] = "Content truncated"
                    break
            
            html_content = content.decode('utf-8', errors='replace')
            evidence["html_summary"] = html_content[:2000] # Store snippet
            
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Extract Title
            if soup.title:
                evidence["title"] = soup.title.string.strip() if soup.title.string else ""
            
            # Extract Text (Safe summary)
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            evidence["text"] = " ".join(chunk for chunk in chunks if chunk)[:5000]
            
            # Extract Metadata
            for meta in soup.find_all("meta"):
                name = meta.get("name", meta.get("property", ""))
                if name:
                    evidence["metadata"][name] = meta.get("content", "")
            
            # Analyze Forms
            for form in soup.find_all("form"):
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": [i.get("name", "") for i in form.find_all("input") if i.get("name")]
                }
                evidence["forms"].append(form_info)
                
                # Suspicious form pattern: Password input in non-HTTPS or sensitive target
                if any(i.get("type") == "password" for i in form.find_all("input")):
                    evidence["suspicious_elements"].append("PASSWORD_FORM")
            
            # Suspicious Elements
            if soup.find_all("iframe"):
                evidence["suspicious_elements"].append("IFRAME_PRESENT")
            
            # JavaScript Indicators
            scripts = soup.find_all("script")
            for s in scripts:
                src = s.get("src", "")
                if src:
                    evidence["javascript_indicators"].append({"type": "external", "src": src})
                else:
                    code = s.string or ""
                    if "eval(" in code:
                        evidence["javascript_indicators"].append({"type": "inline", "feature": "EVAL_DETECTED"})
            
            evidence["status"] = "SUCCESS"
            
        except requests.exceptions.Timeout:
            evidence["status"] = "FAILED"
            evidence["error"] = "Connection Timeout"
        except requests.exceptions.RequestException as e:
            evidence["status"] = "FAILED"
            evidence["error"] = str(e)
        except Exception as e:
            evidence["status"] = "ERROR"
            evidence["error"] = f"Internal processing error: {str(e)}"
            
        return evidence
