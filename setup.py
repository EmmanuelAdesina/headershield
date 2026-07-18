from setuptools import setup, find_packages

setup(
    name="headershield",
    version="2.0.0",
    description="Security header audit engine",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["requests>=2.28.0"],
    entry_points={
        "console_scripts": [
            "headershield=headershield.cli:main",
        ],
    },
    python_requires=">=3.8",
)
