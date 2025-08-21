"""
Setup script for Email Security Analyzer.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
README_PATH = Path(__file__).parent / "README.md"
if README_PATH.exists():
    with open(README_PATH, "r", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "Email Security Analyzer - AI-powered analysis of email security test failures"

# Read requirements
REQUIREMENTS_PATH = Path(__file__).parent / "requirements.txt"
if REQUIREMENTS_PATH.exists():
    with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]
else:
    requirements = [
        "openai>=1.0.0",
        "playwright>=1.40.0",
        "python-dotenv>=1.0.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "beautifulsoup4>=4.12.0",
        "requests>=2.31.0",
    ]

setup(
    name="email-security-analyzer",
    version="1.0.0",
    author="Email Security Team",
    author_email="security@example.com",
    description="AI-powered analysis of email security test failures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourorg/email-security-analyzer",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Communications :: Email",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "enhanced": [
            "rich>=13.0.0",
            "loguru>=0.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "email-security-analyzer=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.md", "*.yml", "*.yaml"],
    },
    keywords="email security testing analysis ai playwright automation",
    project_urls={
        "Bug Reports": "https://github.com/yourorg/email-security-analyzer/issues",
        "Source": "https://github.com/yourorg/email-security-analyzer",
        "Documentation": "https://github.com/yourorg/email-security-analyzer/wiki",
    },
)