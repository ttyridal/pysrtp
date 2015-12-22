#!/usr/bin/env python
from setuptools import setup

setup(
    name='pysrtp',
    version='0.99-git',
    description='library implementing srtp functions',
    author='Torbjorn Tyridal',
    author_email='',
    url='https://github.com/ttyridal/pysrtp',
    packages=['pysrtp'],
    long_description="""\
      transform rtp/rtcp packets suitable for RTP/SAVPF \
      transport.  Somewhat similar to libSRTP.
      """,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Internet Phone",
    ],
    keywords='networking srtp rtp cryptography',
    license='MIT',
    install_requires=[
        'setuptools',
        'pycrypto',
    ],
    #dependency_links=['http://github.com/ttyridal/pysrtp/tarball/master#egg=pysrtp']
    )
