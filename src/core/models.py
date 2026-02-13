"""
Data models for VIPRecon tool.
Defines structured data classes for scan results and related information.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanTarget:
    """Represents a target for reconnaissance scanning."""
    url: str
    domain: str
    ip: Optional[str] = None
    port: int = 443
    protocol: str = "https"
    
    def __str__(self) -> str:
        return f"{self.protocol}://{self.domain}:{self.port}"


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float  # in seconds
    url: str
    
    def __post_init__(self):
        # Ensure headers are case-insensitive
        self.headers = {k.lower(): v for k, v in self.headers.items()}


@dataclass
class Technology:
    """Represents a detected technology."""
    name: str
    version: Optional[str] = None
    category: Optional[str] = None  # e.g., "CMS", "Web Server", "JavaScript Library"
    confidence: float = 0.0  # 0-100
    indicators: List[str] = field(default_factory=list)  # What indicated this technology
    
    def __str__(self) -> str:
        version_str = f" {self.version}" if self.version else ""
        return f"{self.name}{version_str} ({self.confidence:.0f}% confidence)"


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    type: str  # e.g., "XSS", "SQL Injection", "CORS Misconfiguration"
    severity: SeverityLevel
    description: str
    proof: Optional[str] = None  # Proof of concept or evidence
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    remediation: Optional[str] = None
    cve: Optional[str] = None
    
    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.type}: {self.description}"


@dataclass
class Subdomain:
    """Represents a discovered subdomain."""
    name: str
    ip_addresses: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    is_alive: bool = False
    technologies: List[Technology] = field(default_factory=list)
    
    def __str__(self) -> str:
        ips = ", ".join(self.ip_addresses) if self.ip_addresses else "No IP"
        status = f" [{self.status_code}]" if self.status_code else ""
        return f"{self.name} ({ips}){status}"


@dataclass
class Endpoint:
    """Represents an API or web endpoint."""
    path: str
    method: str = "GET"  # HTTP method
    parameters: List[str] = field(default_factory=list)
    source: str = "unknown"  # Where this endpoint was discovered
    status_code: Optional[int] = None
    requires_auth: bool = False
    
    def __str__(self) -> str:
        params = f"?{','.join(self.parameters)}" if self.parameters else ""
        return f"{self.method} {self.path}{params}"


@dataclass
class JavaScriptFinding:
    """Represents findings from JavaScript analysis."""
    file_url: str
    endpoints: List[str] = field(default_factory=list)
    api_keys: List[Dict[str, str]] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    sensitive_data: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class SecurityHeader:
    """Represents a security header check result."""
    header_name: str
    present: bool
    value: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO
    recommendation: Optional[str] = None


@dataclass
class ScanMetadata:
    """Metadata about a scan."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    modules_run: List[str] = field(default_factory=list)
    modules_failed: List[str] = field(default_factory=list)
    tool_version: str = "1.0.1"
    
    def __post_init__(self):
        if self.end_time and self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        else:
            self.duration_seconds = 0.0


@dataclass
class ScanResult:
    """Complete scan results."""
    metadata: ScanMetadata
    target_info: Dict[str, Any] = field(default_factory=dict)
    technologies: List[Technology] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    subdomains: List[Subdomain] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    javascript_findings: List[JavaScriptFinding] = field(default_factory=list)
    security_headers: List[SecurityHeader] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    directory_items: List[Dict[str, Any]] = field(default_factory=list)
    waf_detected: Optional[Dict[str, Any]] = None
    
    def get_vulnerabilities_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Get all vulnerabilities of a specific severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_count(self) -> int:
        """Get count of critical vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(SeverityLevel.CRITICAL))
    
    def get_high_count(self) -> int:
        """Get count of high severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(SeverityLevel.HIGH))
    
    def get_medium_count(self) -> int:
        """Get count of medium severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(SeverityLevel.MEDIUM))
    
    def get_low_count(self) -> int:
        """Get count of low severity vulnerabilities."""
        return len(self.get_vulnerabilities_by_severity(SeverityLevel.LOW))
