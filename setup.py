from setuptools import setup, find_packages

setup(
    name='terrasecure',
    version='1.0.0',
    description='AI-powered Terraform security scanner',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'python-hcl2>=4.3.2',
        'colorama>=0.4.6',
        'click>=8.1.7',
    ],
    entry_points={
        'console_scripts': [
            'terrasecure=src.cli:scan',
        ],
    },
    python_requires='>=3.8',
)