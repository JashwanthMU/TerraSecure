"""
Unit tests for CLI
"""

import unittest
import sys
import os
from pathlib import Path
from click.testing import CliRunner

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from cli import scan, __version__


class TestCLI(unittest.TestCase):
    """Test CLI functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.runner = CliRunner()
    
    def test_version_flag(self):
        """Test --version flag"""
        result = self.runner.invoke(scan, ['--version'])
        
        self.assertIn(result.exit_code, [0, 2])
        self.assertIn(__version__, result.output)
    
    def test_help_flag(self):
        """Test --help flag"""
        result = self.runner.invoke(scan, ['--help'])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn('TerraSecure', result.output)
        self.assertIn('--format', result.output)
        self.assertIn('--fail-on', result.output)
    
    def test_format_options(self):
        """Test format options are available"""
        result = self.runner.invoke(scan, ['--help'])
        
        self.assertIn('text', result.output)
        self.assertIn('json', result.output)
        self.assertIn('sarif', result.output)
    
    def test_fail_on_options(self):
        """Test fail-on options are available"""
        result = self.runner.invoke(scan, ['--help'])
        
        self.assertIn('critical', result.output)
        self.assertIn('high', result.output)
        self.assertIn('medium', result.output)
        self.assertIn('any', result.output)


if __name__ == '__main__':
    unittest.main()