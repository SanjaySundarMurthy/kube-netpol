"""Setup configuration for kube-netpol."""
from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kube-netpol",
    version="1.0.0",
    author="Sai Sandeep",
    author_email="ssan@example.com",
    description="Kubernetes NetworkPolicy generator, validator & visualizer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ssan/kube-netpol",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "kube-netpol=kube_netpol.cli:main",
        ],
    },
    keywords="kubernetes networkpolicy network security firewall visualizer generator",
)
