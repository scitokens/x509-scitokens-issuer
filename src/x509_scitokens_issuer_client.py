#!/usr/bin/python

"""
Utilizing the caller's X509 proxy, act as an OAuth2 client and generate a
corresponding access token.
"""

import os
import sys
import json
import urlparse

import requests

class TokenException(Exception):
    """
    Base class for token-fetching-related exceptions
    """

class DiscoverEndpointException(TokenException):
    """
    Class for errors related to token issuer endpoint discovery.
    """

class TokenIssuerException(TokenException):
    """
    Class for errors related to token issuance.
    """

class TokenArgumentException(TokenException):
    """
    Class for errors related to the parameters passed to the token
    creation functions
    """

def __configure_authenticated_session(cert=None, key=None):
    """
    Generate a new session object for use with requests to the issuer.

    Configures TLS appropriately to work with a GSI environment.
    """
    euid = os.geteuid()
    if euid == 0:
        default_cert = '/etc/grid-security/hostcert.pem'
        default_key = '/etc/grid-security/hostkey.pem'
    else:
        default_cert = '/tmp/x509up_u%d' % euid
        default_key = '/tmp/x509up_u%d' % euid

    if not cert:
        cert = os.environ.get('X509_USER_PROXY', default_cert)
    if not key:
        key = os.environ.get('X509_USER_PROXY', default_key)

    session = requests.Session()

    if os.path.exists(cert):
        session.cert = cert
    if os.path.exists(key):
        session.cert = (cert, key)

    return session


def __get_token_endpoint(issuer):
    """
    From the provided issuer, use OAuth2-style auto-discovery to bootstrap
    the token endpoint.
    """
    if not issuer.endswith("/"):
        issuer += "/"
    config_url = urlparse.urljoin(issuer, ".well-known/openid-configuration")
    response = requests.get(config_url)
    endpoint_info = json.loads(response.text)
    if response.status_code != requests.codes.ok:
        raise DiscoverEndpointException("Failed to access the auto-discovery "
            "URL (%s) for issuer %s (status=%d): %s" % (config_url, issuer, \
            response.status, response.text[:2048]))
    elif 'token_endpoint' not in endpoint_info:
        raise DiscoverEndpointException("Token endpoint not available for issuer "
            "%s" % issuer)
        return False
    return endpoint_info['token_endpoint']


def __generate_token(endpoint, cert=None, key=None):
    """
    Call out to the OAuth2 token issuer, using the client credentials
    grant type, and receive an access token.

    Returns a dictionary based on the server-provided JSON; the following
    keys are customary:

    - `access_token`: the token itself.
    - `token_type`: typically `bearer` for generic tokens or possibly `jwt`.
    - `expires_in`: time, in seconds, until the token expires.
    """
    with __configure_authenticated_session(cert=cert, key=key) as session:
        response = session.post(endpoint, headers={"Accept": "application/json"},
                                data={"grant_type": "client_credentials"})

    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    else:
        raise TokenIssuerException("Issuer failed request (status %d): %s" % \
            (response.status_code, response.text[:2048]))


def get_token(issuer, cert=None, key=None):
    """
    Given a token issuer, return an access token derived from the provided GSI
    credentials

    - `issuer`: URL of the token issuer.
    - `cert`: Filename of the client certificate to use for the TLS connection to
      the access token endpoint.
    - `key`: Filename of the client key to use for the TLS connection to the
      access token endpoint.

    If either `cert` or `key` are None, then the default GSI proxy discovery rules
    will be utilized.

    This returns a python dictionary describing the token; the dictionary will
    contain the token in the `access_token` key.
    """
    endpoint = __get_token_endpoint(issuer)
    return __generate_token(endpoint, cert=cert, key=key)

def get_macaroon(url, cert=None, key=None, validity=5, activity=None):
    """
    Given a URL, try to retrieve a corresponding macaroon for its access.

    - `url`: URL to generate the macaroon for.
    - `cert`: Filename of the client certificate to use for the TLS connection to
      the access token endpoint.
    - `key`: Filename of the client key to use for the TLS connection to the
      access token endpoint.
    - `validity`: Time, in minutes, the macaroon should be valid for.
    - `activity`: A list of activities the token should be authorized to perform.

    If either `cert` or `key` are None, then the default GSI proxy discovery rules
    will be utilized.

    This returns a python dictionary describing the macaroon; the dictionary will
    contain the macaroon in the `macaroon` key.
    """

    # Normalize URL to get rid of the fake "davs" scheme.
    split_result = urlparse.urlsplit(url)
    scheme = split_result.scheme
    if scheme == "davs":
        scheme = "https"
    url = urlparse.urlunsplit(urlparse.SplitResult(scheme=scheme,
                                                   netloc=split_result.netloc,
                                                   path=split_result.path,
                                                   query="",
                                                   fragment="")
                             )

    if validity <= 0:
        TokenArgumentException("Validity period must be a positive integer.")

    if not activity:
        TokenArgumentException("At least one activity must be specified")

    validity = "PT%dM" % validity

    data_json = {"caveats": ["activity:%s" % ",".join(activity)],
                 "validity": validity}
    with __configure_authenticated_session(cert=cert, key=key) as session:
        response = session.post(url,
                                headers={"Content-Type": "application/macaroon-request"},
                                data=json.dumps(data_json)
                               )

    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    else:
        raise TokenIssuerException("Issuer failed request (status %d): %s" % \
            (response.status_code, response.text[:2048]))

