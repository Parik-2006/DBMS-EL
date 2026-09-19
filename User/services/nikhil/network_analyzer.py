import socket
import requests
import tldextract
from urllib.parse import urlparse
import time

class NetworkAnalyzer:
    """Service for collecting network and domain evidence"""
    
    TIMEOUT = 5 # seconds

    @staticmethod
    def analyze_network(url):
        """
        Collect network and domain evidence
        
        Returns:
            dict: Network evidence
        """
        evidence = {
            "status": "PENDING",
            "domain": "",
            "ip": "",
            "dns": {},
            "redirects": [],
            "ssl": {},
            "error": None,
            "timestamp": time.time()
        }
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            if not hostname:
                evidence["status"] = "SKIPPED"
                evidence["error"] = "Invalid hostname"
                return evidence
            
            evidence["domain"] = hostname
            
            # DNS/IP Resolution
            try:
                ip = socket.gethostbyname(hostname)
                evidence["ip"] = ip
                evidence["dns"] = {"resolved_ip": ip}
            except Exception as e:
                evidence["dns"] = {"error": str(e)}

            # Redirection/SSL check
            # We already have response from WebpageAnalyzer, but let's do a lightweight head request to verify
            try:
                # Need verify=True for SSL verification
                response = requests.head(url, timeout=NetworkAnalyzer.TIMEOUT, allow_redirects=True, verify=True)
                
                evidence["redirects"] = [r.url for r in response.history]
                
                # SSL Info
                # requests doesn't expose raw SSL cert easily without lower level tools, 
                # but we can check if it passed SSL verification
                evidence["ssl"] = {"verified": True}
                
            except requests.exceptions.SSLError:
                evidence["ssl"] = {"verified": False, "error": "SSL Verification Failed"}
            except Exception as e:
                evidence["ssl"] = {"error": str(e)}
            
            evidence["status"] = "SUCCESS"
            
        except Exception as e:
            evidence["status"] = "FAILED"
            evidence["error"] = str(e)
            
        return evidence
