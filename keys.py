import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa


def b64url_uint(value):
    #encode an int as base64url with no padding, needed for JWK n/e fields
    byte_len = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_len, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")


class Key:
    def __init__(self, kid, expiry_seconds, key_size=2048):
        self.kid = kid
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.public_key = self.private_key.public_key()
        self.expiry = int(time.time()) + expiry_seconds

    def is_expired(self):
        return time.time() >= self.expiry

    def to_jwk(self):
        nums = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": b64url_uint(nums.n),
            "e": b64url_uint(nums.e),
        }


class KeyManager:
    #keeps one good key and one already-expired key in memory
    def __init__(self):
        self._keys = {}

        active = Key(kid=str(uuid.uuid4()), expiry_seconds=3600)
        self._keys[active.kid] = active
        self.active_kid = active.kid

        expired = Key(kid=str(uuid.uuid4()), expiry_seconds=-3600)
        self._keys[expired.kid] = expired
        self.expired_kid = expired.kid

    def get_active_key(self):
        return self._keys[self.active_kid]

    def get_expired_key(self):
        return self._keys[self.expired_kid]

    def get_key(self, kid):
        return self._keys.get(kid)

    def get_unexpired_jwks(self):
        keys = [k.to_jwk() for k in self._keys.values() if not k.is_expired()]
        return {"keys": keys}
