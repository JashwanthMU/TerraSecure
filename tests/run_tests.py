"""
Test Runner for TerraSecure
"""

import unittest
import sys
from pathlib import Path

def run_tests():
    """Run all tests"""
    
    print("="*70)
    print("TerraSecure Test Suite")
    print("="*70)
    print()
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = Path(__file__).parent / 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print()
    
    if result.wasSuccessful():
        print(" ALL TESTS PASSED!")
        return 0
    else:
        print(" SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(run_tests())