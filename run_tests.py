# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain postgres_pgvector copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Test runner script for the FHIR MCP Server.

This script provides an easy way to run all tests with proper configuration.
"""

import subprocess
import sys
import os


def check_dependencies():
    """Check if test dependencies are installed."""
    try:
        import pytest
        import pytest_asyncio
        import pytest_cov
        return True
    except ImportError as e:
        print("❌ Test dependencies not found!")
        print(f"Missing: {e.name}")
        print("\nTo install test dependencies, run one of:")
        print("  pip install -e .[test]")
        print("  pip install -r requirements-dev.txt")
        print("  uv sync --dev")
        return False


def run_tests():
    """Run all tests with proper Python path and configuration."""
    
    # Check dependencies first
    if not check_dependencies():
        return 1
    
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