"""
Tests for the TechnologyFingerprinter module.
"""

import pytest
from src.modules.fingerprinting import TechnologyFingerprinter
from src.core.models import ScanTarget, HTTPResponse

def test_fingerprint_wordpress():
    """Test detection of WordPress."""
    target = ScanTarget(url="https://example.com", domain="example.com")
    
    # Mock WordPress response
    response = HTTPResponse(
        status_code=200,
        headers={'x-powered-by': 'PHP/7.4'},
        body="""
        <html>
            <head>
                <meta name="generator" content="WordPress 5.8">
                <link rel='stylesheet' href='https://example.com/wp-content/themes/twentytwentyone/style.css'>
            </head>
            <body>Welcome to my blog</body>
        </html>
        """,
        response_time=0.1,
        url="https://example.com"
    )
    
    fingerprinter = TechnologyFingerprinter()
    # We need to run await on the fingerprint method since it might be async in the implementation
    # Based on previous turns, it IS async.
    import asyncio
    technologies = asyncio.run(fingerprinter.fingerprint(target, response))
    
    tech_names = [t.name.lower() for t in technologies]
    assert "wordpress" in tech_names
    assert "php" in tech_names

def test_fingerprint_react_bootstrap():
    """Test detection of React and Bootstrap."""
    target = ScanTarget(url="https://example.com", domain="example.com")
    
    response = HTTPResponse(
        status_code=200,
        headers={},
        body="""
        <html>
            <body>
                <div id="root" data-reactroot=""></div>
                <div class="container"><div class="row"><div class="col-md-12">Hello</div></div></div>
                <script src="/static/js/main.chunk.js"></script>
                <script src="https://cdn.example.com/react.min.js"></script>
            </body>
        </html>
        """,
        response_time=0.1,
        url="https://example.com"
    )
    
    fingerprinter = TechnologyFingerprinter()
    import asyncio
    technologies = asyncio.run(fingerprinter.fingerprint(target, response))
    
    tech_names = [t.name.lower() for t in technologies]
    assert "react" in tech_names
    assert "bootstrap" in tech_names
