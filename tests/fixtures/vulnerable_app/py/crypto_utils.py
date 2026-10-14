import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import DES3, PKCS1_OAEP


def make_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    shared = ec.generate_private_key(ec.SECP256R1()).exchange(ec.ECDH(), peer_public_key)
    return private_key, shared


def wrap(public_key, data):
    return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def legacy(data):
    # hashlib.md5 in a comment must not be reported
    cipher = DES3.new(key, DES3.MODE_CBC)
    checksum = hashlib.md5(data).hexdigest()
    accepted = hashlib.sha1(data).hexdigest()  # postshor:ignore
    return cipher, checksum, accepted


JWT_ALG = "RS256"
