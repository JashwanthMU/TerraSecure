"""
Integration tests for full scanning workflow
"""

import unittest
import sys
import os
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from scanner.analyzer import SecurityAnalyzer


class TestFullScan(unittest.TestCase):
    """Test complete scanning workflow"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.analyzer = SecurityAnalyzer()
        self.test_files_dir = Path(__file__).parent.parent.parent / 'examples' / 'vulnerable'
    
    def test_scan_vulnerable_examples(self):
        """Test scanning vulnerable examples"""
        if not self.test_files_dir.exists():
            self.skipTest("Vulnerable examples not found")
        
        results = self.analyzer.scan_directory(str(self.test_files_dir))
        
        # Should find issues
        self.assertGreater(len(results['issues']), 0)
        
        # Should have statistics
        self.assertIn('stats', results)
        self.assertIn('CRITICAL', results['stats'])
    
    def test_ml_integration(self):
        """Test ML analyzer is integrated"""
        if not self.test_files_dir.exists():
            self.skipTest("Vulnerable examples not found")
        
        results = self.analyzer.scan_directory(str(self.test_files_dir))
        
        # All issues should have ML scores
        for issue in results['issues']:
            self.assertIn('ml_risk_score', issue)
            self.assertIn('ml_confidence', issue)
            self.assertGreaterEqual(issue['ml_risk_score'], 0.0)
            self.assertLessEqual(issue['ml_risk_score'], 1.0)
    
    def test_sarif_generation(self):
        """Test SARIF can be generated from scan results"""
        if not self.test_files_dir.exists():
            self.skipTest("Vulnerable examples not found")
        
        from formatters.sarif_formatter import format_sarif
        
        results = self.analyzer.scan_directory(str(self.test_files_dir))
        
        # Convert to SARIF
        sarif = format_sarif(results['issues'], scan_path=str(self.test_files_dir))
        
        # Verify SARIF structure
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('runs', sarif)


if __name__ == '__main__':
    unittest.main()