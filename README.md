
X.509 / SciTokens Issuer
========================

This simple WSGI application provides a mechanism for issuing SciTokens based on a client
authenticating via a X509 (or VOMS) client credential.

It is a small Flask application which uses Apache 2.4 and mod\_gridsite to handle the TLS
termination and mod\_wsgi to pass the request to the Flask application.  It uses the
scitokens python library for the actual token issuance

Configuration
-------------

A few configuration files should be examined by default:

- `/etc/http/conf.d/x509_scitokens_issuer.conf`: Enables the SciTokens callout and configures Apache to
  listen on port 8443.  *Note* this will listen on port 8443 by default once the package is installed
  and Apache is started.  However, the issuer will not work until it is explicitly enabled
- `/usr/share/x509-scitokens-issuer/x509_scitokens.cfg`: Default configuration options for the application.  Do
  not edit, as this will be overwritten on install.  This file helps illustrate available configuration
  options.
- `/etc/x509-scitokens-issuer/conf.d/`: Directory containing sysadmin-provided overrides.  All files ending in `.cfg`
  are loaded.
- `/etc/x509-scitokens-issuer/issuer_key.json`: Issuer key, JSON-formatted.  This is auto-generated at install time
  if the file is not present (or otherwise empty).  It is not overwritten on upgrade.
- '/etc/x509-scitokens-issuer/rules.json': Set of rules for mapping DNs and VOMS FQANs to scopes.
