"""
Various helper utility functions for the x509_scitokens_issuer package
"""

import base64

import cryptography.utils
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.backends import default_backend
import scitokens

def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)

    return base64.urlsafe_b64decode(data)

def long_from_bytes(data):
    """
    Return an integer from base64-encoded string.

    :param data: UTF-8 string containing base64-encoded data.
    :returns: Corresponding decoded integer.
    """
    return cryptography.utils.int_from_bytes(decode_base64(data.encode("ascii")), 'big')

def load_jwks(jwks_obj):
    """
    Given a JWKS-formatted dictionary representing a private key,
    return a python-cryptography private key object
    """

    if jwks_obj['kty'] == "RSA":
        n = long_from_bytes(jwks_obj['n'])
        e = long_from_bytes(jwks_obj['e'])
        d = long_from_bytes(jwks_obj['d'])
        public_key_numbers = rsa.RSAPublicNumbers(
            e = e,
            n = n,
        )
        # If loading a partial key, we'll have to recalculate a
        # few of the relevant constants
        if ('p' not in jwks_obj) or ('q' not in jwks_obj):
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
        else:
            p = long_from_bytes(jwks_obj['p'])
            q = long_from_bytes(jwks_obj['q'])
        if 'qi' not in jwks_obj:
            qi = rsa.rsa_crt_iqmp(p, q)
        else:
            qi = long_from_bytes(jwks_obj['qi'])
        if 'dp' not in jwks_obj:
            dmp1 = rsa.rsa_crt_dmp1(d, p)
        else:
            dmp1 = long_from_bytes(jwks_obj['dp'])
        if 'dq' not in jwks_obj:
            dmq1 = rsa.rsa_crt_dmq1(d, q)
        else:
            dmq1 = long_from_bytes(jwks_obj['dq'])
        private_key_numbers = rsa.RSAPrivateNumbers(
            p = p,
            q = q,
            d = d,
            dmp1 = dmp1,
            dmq1 = dmq1,
            iqmp = qi,
            public_numbers = public_key_numbers
        )
        return private_key_numbers.private_key(default_backend())
    elif jwks_obj['kty'] == 'EC':
        public_key_numbers = ec.EllipticCurvePublicNumbers(
            long_from_bytes(jwks_obj['x']),
            long_from_bytes(jwks_obj['y']),
            ec.SECP256R1
        )
        private_key_numbers = ec.EllipticCurvePrivateNumbers(
            long_from_bytes(jwks_obj['d']),
            public_key_numbers
        )
        return private_key_numbers.private_key(default_backend())
    else:
        raise scitokens.scitokens.UnsupportedKeyException("Issuer public key not supported.")

