# BYNNΛI - AutomatonSec (https://github.com/BYNNAI/AutomatonSec)

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="automatonsec",
    version="1.0.0",
    author="BYNNΛI",
    author_email="contact@bynnai.dev",
    description="Advanced Smart Contract Security Analysis Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BYNNAI/AutomatonSec",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "z3-solver>=4.13.0.0",
        "py-solc-x>=2.0.3",
        "web3>=6.15.1",
        "slither-analyzer>=0.10.0",
        "torch>=2.2.0",
        "transformers>=4.37.2",
        "scikit-learn>=1.4.0",
        "networkx>=3.2.1",
        "click>=8.1.7",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "loguru>=0.7.2",
    ],
    entry_points={
        "console_scripts": [
            "automatonsec=automatonsec.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "automatonsec": [
            "config/*.yaml",
        ],
    },
)