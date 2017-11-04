"""
Various helper utility functions for the x509_scitokens_issuer package
"""

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.backends import default_backend
import scitokens.scitokens.utils as scitokens_utils.long_from_bytes
import scitokens

def load_jwks(jwks_obj):
    """
    Given a JWKS-formatted dictionary representing a private key,
    return a python-cryptography private key object
    """

    if raw_key['kty'] == "RSA":
        n = scitokens_utils.long_from_bytes(jwks_obj['n'])
        e = scitokens_utils.long_from_bytes(jwks_obj['e'])
        d = scitokens_utils.long_from_bytes(jwks_obj['d'])
        public_key_numbers = rsa.RSAPublicNumbers(
            e = e,
            n = n,
        )
        # If loading a partial key, we'll have to recalculate a
        # few of the relevant constants
        if ('p' not in jwks_obj) or ('q' not in jwks_obj):
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
        else:
            p = scitokens_utils.long_from_bytes(jwks_obj['p'])
            q = scitokens_utils.long_from_bytes(jwks_obj['q'])
        if 'qi' not in jwks_obj:
            qi = rsa.rsa_crt_iqmp(p, q)
        else:
            qi = scitokens_utils.long_from_bytes(jwks_obj['qi'])
        if 'dp' not in jwks_obj:
            dmp1 = rsa.rsa_crt_dmp1(d, p)
        else:
            dmp1 = scitokens_utils.long_from_bytes(jwks_obj['dp'])
        if 'dq' not in jwks_obj:
            dmq1 = rsa.rsa_crt_dmq1(d, q)
        else:
            dmq1 = scitokens_utils.long_from_bytes(jwks_obj['dq'])
        private_key_numbers = rsa.RSAPrivateNumbers(
            p = p,
            q = q,
            d = d,
            dmp1 = dmp1,
            dmq1 = dmq1,
            iqmp = qi,
            public_numbers = public_key_numbers
        )
        return private_key_numbers.private_key()
    elif raw_key['kty'] == 'EC':
        public_key_numbers = ec.EllipticCurvePublicNumbers(
            scitokens_utils.long_from_bytes(jwks_obj['x']),
            scitokens_utils.long_from_bytes(jwks_obj['y']),
            ec.SECP256R1
        )
        private_key_numbers = ec.EllipticCurvePrivateNumbers(
            scitokens_utils.long_from_bytes(jwks_obj['d']),
            public_key_numbers
        )
        return private_key_numbers.private_key()
    else:
        raise scitokens.scitokens.UnsupportedKeyException("Issuer public key not supported.")
