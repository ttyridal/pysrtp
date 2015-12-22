"""SRTP functions for python, with similarities to libSRTP

https://tools.ietf.org/html/rfc3711 - SRTP AES-SHA
https://tools.ietf.org/html/rfc7714 - SRTP AES-GCM
"""
import pkg_resources
from . import srtp
from .errors import *

__author__ = "Torbjorn Tyridal"
__copyright__ = "Copyright 2015, Torbjorn Tyridal"
__credits__ = [
    "Bo Zhu",
    "Goncalo Pinheira",
    "Torbjorn Tyridal",
    ]
__license__ = "MIT"
__version__ = pkg_resources.require('pysrtp')[0].version
__maintainer__ = "Torbjorn Tyridal"
__email__ = ""
__status__ = "Development"
