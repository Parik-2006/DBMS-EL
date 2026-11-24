import socket
import time
import logging
import concurrent.futures
from datetime import datetime

from User.security import outbound
from User.services.domain_normalization import normalize_url

logger = logging.getLogger(__name__)

_rdns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='rdns')


class NetworkAnalyzer:
    """
    Service for collecting network and domain evidence.
    Produces EVIDENCE ONLY. Does not classify URLs independently.

    Phase 1: every outbound action goes through ``User.security.outbound``:
    DNS answers are validated (public addresses only) and pinned; the HEAD
    request and TLS inspection connect to the pinned IP. A destination rejected
    by policy yields status ``BLOCKED`` (never treated as benign). TLS
    ``verified`` is True/False only when a handshake actually completed;
    ``None`` means "could not be determined" (e.g. port 443 closed).
    """

    DNS_TIMEOUT = 3.0  # seconds
    HTTP_TIMEOUT = 4.0  # seconds
    SSL_TIMEOUT = 3.0  # seconds

    @classmethod
    def analyze_network(cls, url):
        evidence = {
            "status": "PENDING",
            "url": url,
            "domain": "",
            "registered_domain": "",
            "tld": "",
            "is_ip_address": False,
            "ip_resolution": {"primary_ip": None, "all_ips": [], "reverse_dns": None, "error": None},
            "dns": {},
            "http_metadata": {"final_url": None, "status_code": None, "server_header": None, "redirect_chain": []},
            "ssl": {
                "is_https": False, "verified": None, "issuer": None, "subject": None,
                "valid_from": None, "valid_until": None, "is_expired": None, "error": None,
            },
            "network_findings": [],
            "security_block": None,
            "error": None,
            "timestamp": time.time(),
        }

        norm = normalize_url(url)
        evidence["domain"] = norm.hostname
        evidence["registered_domain"] = norm.registered_domain
        evidence["tld"] = norm.suffix
        evidence["is_ip_address"] = norm.is_ip
        evidence["ssl"]["is_https"] = norm.scheme == 'https'
        if norm.is_ip:
            evidence["network_findings"].append(f"Target hostname is a raw IP address: {norm.hostname}")

        # 1. Policy validation + DNS resolution (pinned)
        try:
            target = outbound.validate_url(norm.url, dns_timeout=cls.DNS_TIMEOUT)
        except outbound.OutboundBlocked as blocked:
            evidence["status"] = "BLOCKED"
            evidence["security_block"] = blocked.reason
            evidence["error"] = f"Destination blocked by outbound security policy: {blocked.reason}"
            evidence["network_findings"].append(f"Outbound policy blocked destination ({blocked.reason})")
            return evidence
        except outbound.OutboundError as err:
            evidence["status"] = "FAILED"
            evidence["ip_resolution"]["error"] = err.reason
            evidence["error"] = f"DNS resolution failed: {err.reason}"
            evidence["network_findings"].append(f"DNS Resolution failed for {norm.hostname}")
            return evidence

        evidence["ip_resolution"]["primary_ip"] = target.addresses[0]
        evidence["ip_resolution"]["all_ips"] = list(target.addresses)
        evidence["dns"]["canonical_name"] = target.host
        evidence["network_findings"].append(f"Resolved IP: {target.addresses[0]}")

        # Reverse DNS (query goes to the resolver, not to the target)
        try:
            fut = _rdns_pool.submit(socket.gethostbyaddr, target.addresses[0])
            evidence["ip_resolution"]["reverse_dns"] = fut.result(timeout=cls.DNS_TIMEOUT)[0]
        except Exception:
            evidence["ip_resolution"]["reverse_dns"] = None

        # 2. HTTP metadata via pinned HEAD, redirects validated per hop
        try:
            resp = outbound.safe_request(
                target.url, method='HEAD', headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishScan/1.0"},
                max_redirects=3, connect_timeout=cls.HTTP_TIMEOUT, read_timeout=cls.HTTP_TIMEOUT,
                total_timeout=cls.HTTP_TIMEOUT * 2, read_body=False)
            evidence["http_metadata"]["status_code"] = resp.status
            evidence["http_metadata"]["final_url"] = resp.url
            evidence["http_metadata"]["server_header"] = resp.headers.get("Server")
            if resp.history:
                evidence["http_metadata"]["redirect_chain"] = resp.history
                if len(resp.history) > 2:
                    evidence["network_findings"].append(
                        f"Multiple HTTP redirects detected ({len(resp.history) - 1} hops)")
        except outbound.OutboundBlocked as blocked:
            evidence["http_metadata"]["error"] = f"blocked: {blocked.reason}"
            evidence["network_findings"].append(f"Redirect/target blocked by outbound policy ({blocked.reason})")
        except outbound.OutboundError as err:
            evidence["http_metadata"]["error"] = err.reason

        # 3. TLS certificate inspection on the pinned address
        cls._inspect_ssl_certificate(target.url, evidence)

        evidence["status"] = "SUCCESS"
        return evidence

    @classmethod
    def _inspect_ssl_certificate(cls, url, evidence):
        try:
            result = outbound.inspect_tls(url, timeout=cls.SSL_TIMEOUT)
        except (outbound.OutboundBlocked, outbound.OutboundError) as exc:
            evidence["ssl"]["error"] = f"TLS probe not performed: {exc.reason}"
            return
        evidence["ssl"]["verified"] = result["verified"]
        evidence["ssl"]["error"] = result["error"]
        cert = result.get("cert")
        if result["verified"] is False:
            evidence["network_findings"].append("Invalid or untrusted SSL certificate")
        if not cert:
            return
        issuer = {k: v for item in cert.get("issuer", []) for k, v in item}
        subject = {k: v for item in cert.get("subject", []) for k, v in item}
        evidence["ssl"]["issuer"] = issuer
        evidence["ssl"]["subject"] = subject
        evidence["ssl"]["valid_from"] = cert.get("notBefore")
        evidence["ssl"]["valid_until"] = cert.get("notAfter")
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expired = datetime.utcnow() > datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                evidence["ssl"]["is_expired"] = expired
                if expired:
                    evidence["network_findings"].append("SSL certificate has expired")
            except ValueError:
                pass
        evidence["network_findings"].append(f"Valid SSL certificate issued by {issuer.get('commonName', '')}")
