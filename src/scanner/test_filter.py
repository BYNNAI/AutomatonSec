# BYNNΛI - AutomatonSec
# https://github.com/BYNNAI/AutomatonSec

import re
from pathlib import Path
from typing import List, Set


class TestFileFilter:
    """
    Filters out test files from bug bounty repository scans.
    Supports Hardhat, Foundry, Truffle, and other common test patterns.
    """

    def __init__(self):
        self.test_patterns = [
            # Directory patterns
            r"/test/",
            r"/tests/",
            r"/testing/",
            r"/spec/",
            r"/mock/",
            r"/mocks/",
            r"/mocking/",
            r"/fixtures/",
            r"/utils/test",
            
            # Framework specific
            r"/forge-std/",
            r"/foundry/",
            r"/hardhat/",
            r"/truffle/",
            r"/brownie/",
            r"/dapptools/",
            r"/lib/forge-std/",
            r"/node_modules/",
            
            # File name patterns
            r"\.test\.sol$",
            r"\.t\.sol$",
            r"Test\.sol$",
            r"_test\.sol$",
            r"Mock\.sol$",
            r"_mock\.sol$",
            r"Fixture\.sol$",
            r"Helper\.sol$",
            r"_helper\.sol$",
            
            # Specific test files
            r"/Setup\.sol$",
            r"/TestHelpers\.sol$",
            r"/MockOracle\.sol$",
            r"/FakeToken\.sol$",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.test_patterns]
    
    def is_test_file(self, file_path: Path) -> bool:
        """
        Check if a file should be excluded as a test file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file is a test file, False otherwise
        """
        path_str = str(file_path).replace("\\", "/")
        
        for pattern in self.compiled_patterns:
            if pattern.search(path_str):
                return True
        
        return False
    
    def filter_files(self, files: List[Path]) -> List[Path]:
        """
        Filter out test files from a list of paths.
        
        Args:
            files: List of file paths
            
        Returns:
            List of production files (non-test)
        """
        return [f for f in files if not self.is_test_file(f)]
    
    def get_test_files(self, files: List[Path]) -> List[Path]:
        """
        Get only test files from a list of paths.
        
        Args:
            files: List of file paths
            
        Returns:
            List of test files
        """
        return [f for f in files if self.is_test_file(f)]
    
    def add_pattern(self, pattern: str) -> None:
        """
        Add a custom test file pattern.
        
        Args:
            pattern: Regex pattern to match test files
        """
        self.test_patterns.append(pattern)
        self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
