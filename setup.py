from setuptools import setup, find_packages

setup(
    name="pqc_benchmark",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "pqc-benchmark=pqc_benchmark.main:main",
        ],
    },
    python_requires=">=3.7",
)