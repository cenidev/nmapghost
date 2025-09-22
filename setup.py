from setuptools import setup
import os

def read_readme():
    try:
        with open("readme.md", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Professional Network Reconnaissance"

setup(
    name="nmapghost",
    version="1.0",
    author="Cenidev", 
    description="Professional Network Reconnaissance",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    py_modules=["main", "interactive_menu"],  # Especifica los módulos exactos
    install_requires=[
        "rich>=13.7.0",
        "python-nmap>=0.7.1",
    ],
    entry_points={
        "console_scripts": [
            "nmapghost=main:main",  # Punto de entrada correcto
        ],
    },
    python_requires=">=3.7",
)
