from __future__ import absolute_import
from setuptools import find_packages
from setuptools import setup

setup(
    name='Products.zmsPluggableAuthService',
    version='0.1',
    license='ZPL 2.1',
    author='HOFFMANN+LIEBENBERG in association with SNTL Publishing',
    author_email='zms@sntl-publishing.com',
    description='ZMS PluggableAuthService adapter.',
    packages=find_packages(),
    include_package_data=True,
    namespace_packages=['Products'],
    zip_safe=False,
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    install_requires=[
        'six',
        'Products.PluggableAuthService==1.11.0',
        'Zope2==2.13.24',
        'cryptography',
        # 'AccessControl',
        # 'Products.PageTemplates'
        # 'Products.PythonScripts'
    ],
    extras_require = {
        'nginx-sso':  ['itsdangerous',],
    }
    
)
