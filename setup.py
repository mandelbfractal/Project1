from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-pentest-bot",
    version="1.0.0",
    author="AI Pentest Bot Team",
    description="An AI-powered penetration testing bot with automated vulnerability scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mandelbfractal/Project1",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "anthropic>=0.18.0",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "pyyaml>=6.0.1",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "jinja2>=3.1.2",
        "reportlab>=4.0.0",
        "validators>=0.22.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "ai-pentest=src.main:main",
        ],
    },
)
