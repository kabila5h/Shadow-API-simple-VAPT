"""Setup script for Shadow API Scanner."""
from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="shadow-api-scanner",
    version="1.0.0",
    description="Automated Shadow API Detection & Security Testing Tool for SPAs",
    author="Security Engineering Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "shadow-scan=shadow_api_scanner.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
