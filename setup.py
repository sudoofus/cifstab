import setuptools
import os, stat

with open('README.md', 'r') as fh:
    long_description = fh.read()


setuptools.setup(
    name='cifstab',
    version='1.0.36',
    description='Mount cifs shares using encrypted passwords',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Darren Chambers',
    author_email='dazchambers@gmail.com',
    url='https://github.com/sudoofus/cifstab',
    packages=setuptools.find_packages(),
    install_requires=[
        'cryptography',
        'argparse',
        'pexpect',
        'regex'
        ],
    entry_points = { 'console_scripts':['cifscloak = cifstab.cifstab:main', 'cifstab = cifstab.cifstab:main'] }
)
