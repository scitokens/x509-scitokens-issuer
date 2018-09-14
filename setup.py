"""
Install file for X509-authentication-based SciTokens issuer.
"""

import setuptools
import platform

# adjust user directory based on our system
# for Darin based system we need to use /usr/local to avoid SIP problem on OSX
# while on Linux we should use /usr according to RHEL standards
# if necessary adjust line below to cover other use cases
udir = '/usr/local' if platform.system() == 'Darwin' else '/usr'

setuptools.setup(name="x509-scitokens-issuer",
                 version="0.4.1",
                 description="SciTokens issuer based on X509/VOMS authentication",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["x509_scitokens_issuer"],
                 scripts=['tools/cms-update-mapping', 'tools/cms-scitoken-init', 'tools/x509-scitoken-init'],
                 data_files=[('/etc/httpd/conf.d', ['configs/x509_scitokens_issuer.conf']),
                             ('%s/share/x509-scitokens-issuer' % udir, ['configs/x509_scitokens_issuer.cfg']),
                             ('%s/lib/systemd/system' % udir, ['configs/cms-mapping-updater.service', 'configs/cms-mapping-updater.timer']),
                             ('/var/cache/httpd/x509-scitokens-issuer', ['configs/dn_mapping.json']),
                             ('/etc/x509-scitokens-issuer', ['configs/rules.json']),
                             ('/etc/x509-scitokens-issuer/conf.d', ['configs/00-defaults.cfg']),
                             ('/var/www/wsgi-scripts', ['wsgi/x509-scitokens-issuer.wsgi']),
                            ],
                 install_requires=['scitokens>=0.3.1',
                                   'Flask',
                                   'gunicorn',
                                   'requests'],
                )
