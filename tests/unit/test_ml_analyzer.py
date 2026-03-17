"""
Unit tests for ML Analyzer
"""

import unittest
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from ml.ml_analyzer import MLAnalyzer


class TestMLAnalyzer(unittest.TestCase):
    """Test ML Analyzer functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test fixtures"""
        cls.analyzer = MLAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsNotNone(self.analyzer.extractor)
    
    def test_model_loaded(self):
        """Test production model is loaded"""
        self.assertTrue(self.analyzer.is_ready())
        info = self.analyzer.get_model_info()
        self.assertEqual(info['status'], 'loaded')
        self.assertIn('version', info)
    
    def test_model_version(self):
        """Test model has correct version"""
        info = self.analyzer.get_model_info()
        self.assertEqual(info['version'], '1.0.0')
    
    def test_model_performance(self):
        """Test model meets performance thresholds"""
        info = self.analyzer.get_model_info()
        perf = info['performance']
        
        # Accuracy > 85%
        self.assertGreater(perf['accuracy'], 0.85)
        
        # False positive rate < 15%
        self.assertLess(perf['false_positive_rate'], 0.15)
        
        # False negative rate < 10%
        self.assertLess(perf['false_negative_rate'], 0.10)
    
    def test_analyze_risky_resource(self):
        """Test analysis of risky resource"""
        risky_resource = {
            'type': 'aws_s3_bucket',
            'name': 'test_bucket',
            'properties': {
                'acl': 'public-read',
                'versioning': {'enabled': False},
                'server_side_encryption_configuration': None
            }
        }
        
        result = self.analyzer.analyze(risky_resource)
        
        self.assertIn('ml_risk_score', result)
        self.assertIn('ml_confidence', result)
        self.assertIn('ml_prediction', result)
        
        # Should detect as risky
        self.assertGreater(result['ml_risk_score'], 0.5)
        self.assertEqual(result['ml_prediction'], 'RISKY')
    
    def test_analyze_safe_resource(self):
        """Test analysis of safe resource"""
        safe_resource = {
            'type': 'aws_s3_bucket',
            'name': 'secure_bucket',
            'properties': {
                'acl': 'private',
                'versioning': {'enabled': True},
                'server_side_encryption_configuration': {
                    'rule': {
                        'apply_server_side_encryption_by_default': {
                            'sse_algorithm': 'AES256'
                        }
                    }
                }
            }
        }
        
        result = self.analyzer.analyze(safe_resource)
        
        # Should detect as safe (or at least lower risk)
        self.assertLess(result['ml_risk_score'], 0.8)
    
    def test_triggered_features(self):
        """Test triggered features are returned"""
        resource = {
            'type': 'aws_s3_bucket',
            'name': 'test',
            'properties': {
                'acl': 'public-read',
                'versioning': {'enabled': False}
            }
        }
        
        result = self.analyzer.analyze(resource)
        
        self.assertIn('triggered_features', result)
        self.assertIsInstance(result['triggered_features'], list)
    
    def test_model_info_structure(self):
        """Test model info has expected structure"""
        info = self.analyzer.get_model_info()
        
        self.assertIn('status', info)
        self.assertIn('version', info)
        self.assertIn('features', info)
        self.assertIn('training_samples', info)
        self.assertIn('performance', info)
        
        perf = info['performance']
        self.assertIn('accuracy', perf)
        self.assertIn('precision', perf)
        self.assertIn('recall', perf)


if __name__ == '__main__':
    unittest.main()