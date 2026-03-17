"""
Unit tests for SARIF Formatter
"""

import unittest
import json
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from formatters.sarif_formatter import SARIFFormatter, format_sarif


class TestSARIFFormatter(unittest.TestCase):
    """Test SARIF Formatter functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.formatter = SARIFFormatter(tool_name="TestTool", tool_version="1.0.0")
        
        self.sample_findings = [
            {
                'rule_id': 'TEST-001',
                'title': 'Test Security Issue',
                'description': 'This is a test security issue',
                'severity': 'critical',
                'file': 'test.tf',
                'line': 10,
                'resource': 'aws_s3_bucket.test',
                'ml_risk_score': 0.95,
                'ml_confidence': 0.92,
                'remediation': 'Fix the issue',
                'references': ['https://example.com']
            }
        ]
    
    def test_formatter_initialization(self):
        """Test formatter initializes correctly"""
        self.assertEqual(self.formatter.tool_name, "TestTool")
        self.assertEqual(self.formatter.tool_version, "1.0.0")
    
    def test_sarif_version(self):
        """Test SARIF version is correct"""
        sarif = self.formatter.format(self.sample_findings)
        
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('$schema', sarif)
    
    def test_sarif_structure(self):
        """Test SARIF has correct structure"""
        sarif = self.formatter.format(self.sample_findings)
        
        self.assertIn('version', sarif)
        self.assertIn('runs', sarif)
        self.assertEqual(len(sarif['runs']), 1)
        
        run = sarif['runs'][0]
        self.assertIn('tool', run)
        self.assertIn('results', run)
    
    def test_tool_information(self):
        """Test tool information in SARIF"""
        sarif = self.formatter.format(self.sample_findings)
        
        driver = sarif['runs'][0]['tool']['driver']
        self.assertEqual(driver['name'], "TestTool")
        self.assertEqual(driver['version'], "1.0.0")
        self.assertIn('rules', driver)
    
    def test_rules_generated(self):
        """Test rules are generated from findings"""
        sarif = self.formatter.format(self.sample_findings)
        
        rules = sarif['runs'][0]['tool']['driver']['rules']
        self.assertEqual(len(rules), 1)
        
        rule = rules[0]
        self.assertEqual(rule['id'], 'TEST-001')
        self.assertIn('name', rule)
        self.assertIn('shortDescription', rule)
    
    def test_results_generated(self):
        """Test results are generated from findings"""
        sarif = self.formatter.format(self.sample_findings)
        
        results = sarif['runs'][0]['results']
        self.assertEqual(len(results), 1)
        
        result = results[0]
        self.assertEqual(result['ruleId'], 'TEST-001')
        self.assertIn('level', result)
        self.assertIn('message', result)
        self.assertIn('locations', result)
    
    def test_severity_mapping(self):
        """Test severity is correctly mapped"""
        findings = [
            {'rule_id': 'T1', 'title': 'T', 'severity': 'critical', 'file': 't.tf', 'line': 1},
            {'rule_id': 'T2', 'title': 'T', 'severity': 'high', 'file': 't.tf', 'line': 1},
            {'rule_id': 'T3', 'title': 'T', 'severity': 'medium', 'file': 't.tf', 'line': 1},
        ]
        
        sarif = self.formatter.format(findings)
        results = sarif['runs'][0]['results']
        
        # Critical and High should be 'error'
        self.assertEqual(results[0]['level'], 'error')
        self.assertEqual(results[1]['level'], 'error')
        
        # Medium should be 'warning'
        self.assertEqual(results[2]['level'], 'warning')
    
    def test_security_severity(self):
        """Test security severity property"""
        sarif = self.formatter.format(self.sample_findings)
        
        rule = sarif['runs'][0]['tool']['driver']['rules'][0]
        self.assertIn('properties', rule)
        self.assertIn('security-severity', rule['properties'])
        
        # Critical should be 9.0
        self.assertEqual(rule['properties']['security-severity'], '9.0')
    
    def test_location_information(self):
        """Test location information in results"""
        sarif = self.formatter.format(self.sample_findings)
        
        result = sarif['runs'][0]['results'][0]
        location = result['locations'][0]['physicalLocation']
        
        self.assertIn('artifactLocation', location)
        self.assertIn('region', location)
        
        self.assertEqual(location['region']['startLine'], 10)
    
    def test_ml_properties(self):
        """Test ML risk properties are included"""
        sarif = self.formatter.format(self.sample_findings)
        
        result = sarif['runs'][0]['results'][0]
        props = result['properties']
        
        self.assertIn('ml_risk_score', props)
        self.assertIn('ml_confidence', props)
        self.assertEqual(props['ml_risk_score'], 0.95)
        self.assertEqual(props['ml_confidence'], 0.92)
    
    def test_format_sarif_function(self):
        """Test convenience function"""
        sarif = format_sarif(self.sample_findings, scan_path='.')
        
        self.assertIn('version', sarif)
        self.assertEqual(sarif['version'], '2.1.0')
    
    def test_empty_findings(self):
        """Test SARIF generation with no findings"""
        sarif = self.formatter.format([])
        
        self.assertEqual(len(sarif['runs'][0]['results']), 0)
        self.assertEqual(len(sarif['runs'][0]['tool']['driver']['rules']), 0)


if __name__ == '__main__':
    unittest.main()