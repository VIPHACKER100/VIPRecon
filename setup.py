from setuptools import setup, find_packages

setup(
    name="viprecon",
    version="1.0.0",
    author="Aryan Ahirwar (viphacker100)",
    description="A comprehensive web application reconnaissance and security testing tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/youruser/VIPRecon",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "aiofiles",
        "beautifulsoup4",
        "dnspython",
        "python-whois",
        "jinja2",
        "colorama",
        "pyyaml",
        "tldextract",
        "validators",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-asyncio",
            "pytest-cov",
            "black",
            "flake8",
            "bandit",
        ],
    },
    entry_points={
        "console_scripts": [
            "viprecon=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
