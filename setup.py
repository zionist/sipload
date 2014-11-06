from distutils.core import setup
from setuptools import setup, find_packages

setup( name='sipload',
    version='0.1',
    description='Sip load tool',
    author='Stas Kridzanovskiy',
    author_email='slaviann@gmail.com',
    packages=find_packages(),
      install_requires=[
          'twisted',
          'dpkt-fix',
      ],
    scripts=['bin/get_calls'],

    )
