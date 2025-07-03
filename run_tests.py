#!/usr/bin/env python3
"""
Test runner script for the FHIR MCP Server.

This script provides an easy way to run all tests with proper configuration.
"""

import subprocess
import sys
import os


def run_tests():
    """Run all tests with proper Python path and configuration."""
    
    # Set up the environment
    project_root = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(project_root, 'src')
    
    # Set PYTHONPATH
    env = os.environ.copy()
    env['PYTHONPATH'] = src_path
    
    # Run pytest with coverage
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/',
        '-v',
        '--cov=src/fhir_mcp_server',
        '--cov-report=term-missing',
        '--cov-report=html:htmlcov'
    ]
    
    print(f"Running tests with command: {' '.join(cmd)}")
    print(f"PYTHONPATH: {src_path}")
    print("-" * 50)
    
    result = subprocess.run(cmd, env=env, cwd=project_root)
    return result.returncode


if __name__ == '__main__':
    exit_code = run_tests()
    if exit_code == 0:
        print("\n" + "=" * 50)
        print("✅ All tests passed successfully!")
        print("📊 Coverage report generated in htmlcov/index.html")
    else:
        print("\n" + "=" * 50)
        print("❌ Some tests failed. Please check the output above.")
    
    sys.exit(exit_code)