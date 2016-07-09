# coding=utf-8
import sys

from pip.download import PipSession
from pip.req import parse_requirements
from setuptools import setup, find_packages

if not sys.version_info.major == 2 and sys.version_info.minor == 7:
    sys.exit("Sorry, Python 3 is not supported")

# parse requirements
install_reqs = parse_requirements("requirements.txt",
                                  session=PipSession())
# reqs is a list of requirements
reqs = [str(ir.req) for ir in install_reqs]
pkgs = find_packages(exclude=["tests"])
# magic function for including subpackages in repo
# can list packages with subpackages explicitly later
setup(
    name='sniffer',
    version='0.0',
    packages=pkgs,
    url='http://davidkarapetyan.com',
    license='Proprietary',
    author='David Karapetyan',
    author_email='david.karapetyan@gmail.com',
    description=(
        'An occupancy sniffer and tracker for restaurants and other '
        'local businesses'
    ),
    scripts=['bin/run_sniffer'],
    install_requires=reqs
)
