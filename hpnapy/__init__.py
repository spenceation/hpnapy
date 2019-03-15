# -*- coding: utf-8 -*-

"""
HP Network Automation Python API client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The hpnapy library provides API acceess to the SOAP API of HP Network Automation.
Basic usage:

   >>> from hpnapy import NAInterface
   >>> hpna = NAInterface("https://foo.bar")
   >>> hpna.login('username', 'password')
   >>> device_groups = hpna.list_device_groups()

:license: GNU General Public License v3.0, see LICENSE for more details.

"""

__title__ = 'HPNA Python Library'
__version__ = '1.0.6'
__author__ = 'Spencer Ervin'
__license__ = 'GNU General Public License v3.0'

from .hpnapy import NAInterface
