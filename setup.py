import setuptools
import os, stat

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='cifscloak',
    version='1.0.22',
    description='Mount cifs shares using encrypted passwords',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Darren Chambers',
    author_email='dazchambers@gmail.com',
    url='https://github.com/sudoofus/cifscloak',
    packages=setuptools.find_packages(),
    install_requires=[
	'cryptography',
	'argparse',
	'regex',
    ],
    entry_points = { 'console_scripts':['cifscloak = cifscloak.cifscloak:main'] }
)
