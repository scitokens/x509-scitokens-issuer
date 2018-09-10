
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
  are loaded.  Customizations must go here; file format is INI-style.
- `/etc/x509-scitokens-issuer/issuer_key.json`: Issuer key, JSON-formatted.  This is auto-generated at install time
  if the file is not present (or otherwise empty).  It is not overwritten on upgrade.
- `/etc/x509-scitokens-issuer/rules.json`: Set of rules for mapping DNs and VOMS FQANs to scopes.

Issuer Configuration
--------------------

Two configuration values must be given in order to produce tokens.  Create a file, `99-local.cfg` in the directory
`/etc/x509-scitokens-issuer/conf.d` and add at least `ENABLED` and `ISSUER`: 

```
# Enable the issuer
ENABLED=True
# Specify the issuer ID that should be included in tokens
ISSUER="https://scitokens.org/cms"
```

For more details about the issuer format, see https://scitokens.org.

Mapping Rules and Mapping File
------------------------------

The `rules.json` file is a list of rules in JSON format that specify what scopes are issued to clients.

For example, the following configuration has a single rule with :
```
{
  "rules": [
    {"match": "fqan:/cms", "scopes": ["read:/store", "write:/store/user/{username}"]}
  ]
}
```

In this case, clients with VOMS FQAN `/cms` will be able to read from `/store` and write into `/store/user/{username}`.
Here, `{username}` is substituted with a username from the `DN_MAPPING` file (defaults to
`/etc/x509-scitokens-issuer/dteam_dn_mapping.json`).  This file is again a JSON-formatted file, mapping from DNs to
a user name.  Example contents are:

```
{"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=bbockelm/CN=659869/CN=Brian Paul Bockelman": "bbockelm",
 "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=jdoe/CN=123456/CN=John Doe": "jdoe",
 "/DC=org/DC=opensciencegrid/O=Open Science Grid/OU=People/CN=Jane Doe": "jane"
}
```

So, if Jane Doe (with DN `/DC=org/DC=opensciencegrid/O=Open Science Grid/OU=People/CN=Jane Doe`) authenticated with a CMS VOMS
proxy on this host, then she would get scopes `read:/store` and `write:/store/user/jane`.
