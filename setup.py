from setuptools import setup, find_packages

setup(
    name="cert_scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "streamlit",
        "sqlalchemy",
        "cryptography",
        "pytest",
        "pytest-mock",
        "pytest-cov",
    ],
    python_requires=">=3.8",
) 