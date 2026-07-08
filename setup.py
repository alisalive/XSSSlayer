from setuptools import setup

setup(
    name="xssslayer",
    version="1.0.0",
    author="alisalive",
    description="High-Performance Intelligent XSS Scanner",
    python_requires=">=3.10",
    py_modules=["xss_slayer", "xssslayer_entry"],
    install_requires=[
        "playwright>=1.51.0",
        "rich==13.7.1",
        "aiohttp==3.11.11",
        "beautifulsoup4==4.12.3",
    ],
    entry_points={
        "console_scripts": [
            "xssslayer = xssslayer_entry:main",
        ],
    },
)
