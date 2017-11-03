"""
Install file for X509-authentication-based SciTokens issuer.
"""

import setuptools

setuptools.setup(name="x509-scitokens-issuer",
                 version="0.1.0",
                 description="SciTokens issuer based on X509/VOMS authentication",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["x509_scitokens_issuer"],
                 scripts=['tools/cms-update-mapping'],
                 data_files=[('/etc/httpd/conf.d', ['configs/x509_scitokens_issuer.conf']),
                             ('/usr/share/x509-scitokens-issuer', ['configs/x509_scitokens_issuer.cfg']),
                             ('/usr/lib/systemd/system', ['configs/cms-mapping-updater.service', 'configs/cms-mapping-updater.timer']),
                             ('/var/cache/httpd/x509-scitokens-issuer', ['configs/dn_mapping.json']),
                             ('/etc/x509-scitokens-issuer', ['configs/rules.json']),
                             ('/etc/x509-scitokens-issuer/conf.d', ['configs/00-defaults.cfg'])
                            ],
                 install_requires=['scitokens>=0.3.1',
                                   'Flask',
                                   'gunicorn',
                                   'requests'],
                )
