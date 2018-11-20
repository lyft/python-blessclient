from setuptools import setup, find_packages

setup(
    name="blessclient",
    version="0.3.0",
    packages=find_packages(exclude=["test*"]),
    install_requires=[
        'boto3>=1.4.0,<2.0.0',
        'psutil>=4.3',
        'kmsauth>=0.1.8',
        'six',
        'hvac',
        'requests_aws_sign'
    ],
    author="Chris Steipp",
    author_email="csteipp@lyft.com",
    description="Issue temporary certificates for ssh, signed by the Netflix BLESS lambda.",
    license="apache2",
    url="https://github.com/lyft/python-blessclient",
    entry_points={
        "console_scripts": [
            "blessclient = blessclient.client:main",
            "bssh = blesswrapper.sshclient:main"
        ],
    },
)
