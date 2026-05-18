import time
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MITRECVEClient:
    def __init__(self):
        self.base_url = "https://cveawg.mitre.org/api/cve/"
        self.session = self._build_session()
        
        # Rate limiting: max 10 requests per second (0.1 seconds per request)
        self.rate_limit_delay = 0.11  # slightly above 0.1 to be safe

    def _build_session(self) -> requests.Session:
        """Builds a requests session with robust retry logic."""
        session = requests.Session()
        
        # Retry up to 3 times on typical server/rate-limit errors
        retries = Retry(
            total=3,
            backoff_factor=1, # 1s, 2s, 4s wait between retries
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        
        return session

    def fetch_cve_details(self, cve_id: str) -> dict:
        """Fetches and parses CVE details from the MITRE API."""
        time.sleep(self.rate_limit_delay) # Enforce rate limit
        
        url = f"{self.base_url}{cve_id}"
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._parse_cve_data(data, cve_id)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch details for {cve_id}: {e}")
            return {"cve_id": cve_id, "error": str(e)}

    def _parse_cve_data(self, data: dict, cve_id: str) -> dict:
        """
        Extracts only the required fields from the MITRE API v5 schema.
        Using .get() heavily to gracefully handle missing nested data.
        """
        cna = data.get("containers", {}).get("cna", {})
        metadata = data.get("cveMetadata", {})
        
        # 1. Published Date
        published_date = metadata.get("datePublished")
        
        # 2. Description
        descriptions = cna.get("descriptions", [])
        description = descriptions[0].get("value") if descriptions else None
        
        # 3. CVSS Score (Looking for v3.1 or v3.0)
        metrics = cna.get("metrics", [])
        cvss_score = None
        for metric in metrics:
            if "cvssV3_1" in metric:
                cvss_score = metric["cvssV3_1"].get("baseScore")
                break
            elif "cvssV3_0" in metric:
                cvss_score = metric["cvssV3_0"].get("baseScore")
                break

        # 4. References
        references_data = cna.get("references", [])
        references = [ref.get("url") for ref in references_data if "url" in ref]
        
        # 5. Affected Products
        affected_data = cna.get("affected", [])
        affected_products = [item.get("product") for item in affected_data if "product" in item]

        return {
            "cve_id": cve_id,
            "published_date": published_date,
            "description": description,
            "cvss_score": cvss_score,
            "references": references,
            "affected_products": affected_products
        }