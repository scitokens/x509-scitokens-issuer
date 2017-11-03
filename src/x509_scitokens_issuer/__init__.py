"""
Flask-based application for issuing SciTokens when behind
a GridSite-enabled Apache service.
"""

from .x509_scitokens_issuer import app
