import socket
import ssl
import requests
import tldextract
from urllib.parse import urlparse
from datetime import datetime
import time
import logging

logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    """
    Service for collecting network and domain evidence.
    Produces EVIDENCE ONLY. Does not classify URLs independently.
    Strict timeouts on all network calls.
    """
    
    DNS_TIMEOUT = 3.0  # seconds
    HTTP_TIMEOUT = 4.0 # seconds
    SSL_TIMEOUT = 3.0  # seconds

    @classmethod
    def analyze_network(cls, url):
        """
        Collect network, DNS, and SSL evidence for a given URL.
        
        Args:
            url: str target URL
            
        Returns:
            dict: Structured network evidence
        """
        evidence = {
            "status": "PENDING",
            "url": url,
            "domain": "",
            "registered_domain": "",
            "tld": "",
            "is_ip_address": False,
            "ip_resolution": {
                "primary_ip": None,
                "all_ips": [],
                "reverse_dns": None,
                "error": None
            },
            "dns": {},
            "http_metadata": {
                "final_url": None,
                "status_code": None,
                "server_header": None,
                "redirect_chain": []
            },
            "ssl": {
                "is_https": False,
                "verified": False,
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_until": None,
                "is_expired": None,
                "error": None
            },
            "network_findings": [],
            "error": None,
            "timestamp": time.time()
        }

        # Parse hostname
        try:
            target_url = url if url.startswith(('http://', 'https://')) else f"http://{url}"
            parsed = urlparse(target_url)
            hostname = parsed.hostname or url.split('/')[0].split(':')[0]
            evidence["domain"] = hostname
            evidence["ssl"]["is_https"] = parsed.scheme.lower() == 'https'

            # Domain extraction using tldextract
            ext = tldextract.extract(hostname)
            if ext.suffix:
                evidence["registered_domain"] = f"{ext.domain}.{ext.suffix}".lower()
                evidence["tld"] = ext.suffix.lower()
            else:
                evidence["registered_domain"] = hostname.lower()

            # Check if hostname is an IP address
            try:
                socket.inet_aton(hostname)
                evidence["is_ip_address"] = True
                evidence["network_findings"].append(f"Target hostname is a raw IP address: {hostname}")
            except socket.error:
                evidence["is_ip_address"] = False

        except Exception as e:
            evidence["status"] = "FAILED"
            evidence["error"] = f"Failed to parse URL/hostname: {str(e)}"
            return evidence

        # 1. DNS & IP Resolution
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(cls.DNS_TIMEOUT)
            
            try:
                host_info = socket.gethostbyname_ex(hostname)
                primary_ip = host_info[2][0] if host_info[2] else None
                all_ips = host_info[2]
                evidence["ip_resolution"]["primary_ip"] = primary_ip
                evidence["ip_resolution"]["all_ips"] = all_ips
                evidence["dns"]["canonical_name"] = host_info[0]
                evidence["dns"]["aliases"] = host_info[1]
                evidence["network_findings"].append(f"Resolved IP: {primary_ip}")

                # Reverse DNS PTR lookup
                if primary_ip:
                    try:
                        rev_lookup = socket.gethostbyaddr(primary_ip)
                        evidence["ip_resolution"]["reverse_dns"] = rev_lookup[0]
                    except Exception:
                        evidence["ip_resolution"]["reverse_dns"] = None

            except socket.gaierror as dns_err:
                evidence["ip_resolution"]["error"] = f"DNS resolution failed: {str(dns_err)}"
                evidence["network_findings"].append(f"DNS Resolution failed for {hostname}")
            finally:
                socket.setdefaulttimeout(old_timeout)

        except Exception as e:
            evidence["ip_resolution"]["error"] = str(e)

        # 2. HTTP Metadata and Redirect Chain
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishScan/1.0"}
            resp = requests.head(target_url, headers=headers, timeout=cls.HTTP_TIMEOUT, allow_redirects=True)
            
            evidence["http_metadata"]["status_code"] = resp.status_code
            evidence["http_metadata"]["final_url"] = resp.url
            evidence["http_metadata"]["server_header"] = resp.headers.get("Server")
            
            if resp.history:
                evidence["http_metadata"]["redirect_chain"] = [r.url for r in resp.history] + [resp.url]
                if len(resp.history) > 1:
                    evidence["network_findings"].append(f"Multiple HTTP redirects detected ({len(resp.history)} hops)")
                    
        except requests.exceptions.RequestException as req_err:
            evidence["http_metadata"]["error"] = str(req_err)

        # 3. SSL / TLS Certificate Analysis (for HTTPS or on port 443)
        if evidence["ssl"]["is_https"] or evidence.get("domain"):
            cls._inspect_ssl_certificate(hostname, evidence)

        evidence["status"] = "SUCCESS"
        return evidence

    @classmethod
    def _inspect_ssl_certificate(cls, hostname, evidence):
        """Fetch and parse SSL certificate information safely"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=cls.SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    evidence["ssl"]["verified"] = True
                    
                    # Extract issuer
                    issuer_dict = {}
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            issuer_dict[k] = v
                    evidence["ssl"]["issuer"] = issuer_dict
                    
                    # Extract subject
                    subj_dict = {}
                    for item in cert.get("subject", []):
                        for k, v in item:
                            subj_dict[k] = v
                    evidence["ssl"]["subject"] = subj_dict

                    # Expiration check
                    not_after_str = cert.get("notAfter")
                    not_before_str = cert.get("notBefore")
                    evidence["ssl"]["valid_from"] = not_before_str
                    evidence["ssl"]["valid_until"] = not_after_str
                    
                    if not_after_str:
                        not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        is_expired = datetime.utcnow() > not_after_dt
                        evidence["ssl"]["is_expired"] = is_expired
                        if is_expired:
                            evidence["network_findings"].append("SSL certificate has expired")
                            
                    issuer_cn = issuer_dict.get("commonName", "")
                    evidence["network_findings"].append(f"Valid SSL certificate issued by {issuer_cn}")

        except ssl.SSLCertVerificationError as ssl_verify_err:
            evidence["ssl"]["verified"] = False
            evidence["ssl"]["error"] = f"SSL Verification Error: {str(ssl_verify_err)}"
            evidence["network_findings"].append("Invalid or untrusted SSL certificate")
        except socket.timeout:
            evidence["ssl"]["error"] = "SSL connection timed out"
        except ConnectionRefusedError:
            evidence["ssl"]["error"] = "Port 443 Connection Refused"
        except Exception as ssl_err:
            evidence["ssl"]["error"] = str(ssl_err)
