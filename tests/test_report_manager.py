"""
Tests for the ReportManager and report generators.
"""

import pytest
import os
import shutil
import json
from pathlib import Path
from datetime import datetime
from src.reports.report_manager import ReportManager
from src.core.models import ScanResult, ScanMetadata, Technology, SeverityLevel

@pytest.fixture
def temp_output_dir(tmp_path):
    """Provide a temporary output directory."""
    dir_path = tmp_path / "output"
    dir_path.mkdir()
    yield str(dir_path)
    # shutil.rmtree(dir_path) # tmp_path handles this

@pytest.fixture
def dummy_scan_result():
    """Provide a dummy ScanResult object."""
    metadata = ScanMetadata(
        target="https://example.com",
        start_time=datetime.now(),
        end_time=datetime.now(),
        modules_run=["basic_info", "fingerprint"]
    )
    
    return ScanResult(
        metadata=metadata,
        technologies=[
            Technology(name="Apache", confidence=100.0, category="Web Server")
        ],
        target_info={"http_headers": {"server": "Apache"}}
    )

def test_json_report_generation(temp_output_dir, dummy_scan_result):
    """Test generating a JSON report."""
    manager = ReportManager(temp_output_dir)
    json_path = manager.generate_json(dummy_scan_result, "test_report")
    
    assert os.path.exists(json_path)
    assert json_path.endswith(".json")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        assert data['scan_metadata']['target'] == "https://example.com"
        assert len(data['technologies']) == 1
        assert data['technologies'][0]['name'] == "Apache"

def test_html_report_generation(temp_output_dir, dummy_scan_result):
    """Test generating an HTML report."""
    manager = ReportManager(temp_output_dir)
    html_path = manager.generate_html(dummy_scan_result, "test_report")
    
    assert os.path.exists(html_path)
    assert html_path.endswith(".html")
    
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "https://example.com" in content
        assert "Apache" in content
        assert "Detected Technologies" in content

def test_manager_cleanup(temp_output_dir, dummy_scan_result):
    """Test report manager cleanup logic."""
    manager = ReportManager(temp_output_dir)
    
    # Generate 15 reports
    for i in range(15):
        manager.generate_json(dummy_scan_result, f"report_{i}")
        
    # Check count
    reports = manager.list_reports()
    assert len(reports['json']) == 15
    
    # Cleanup (keep only 10)
    manager.cleanup_old_reports(keep_count=10)
    
    reports = manager.list_reports()
    assert len(reports['json']) == 10
