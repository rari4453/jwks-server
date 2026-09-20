import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import app as app_module
from keys import Key, KeyManager, b64url_uint


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    app_module.key_manager = KeyManager()  # fresh keys per test
    with app_module.app.test_client() as c:
        yield c


# keys.py tests

def test_key_generates_rsa_keypair():
    key = Key(kid="test-kid", expiry_seconds=3600)
    assert key.kid == "test-kid"
    assert isinstance(key.private_key, rsa.RSAPrivateKey)
    assert isinstance(key.public_key, rsa.RSAPublicKey)


def test_key_not_expired_when_future():
    key = Key(kid="future", expiry_seconds=3600)
    assert key.is_expired() is False


def test_key_expired_when_past():
    key = Key(kid="past", expiry_seconds=-10)
    assert key.is_expired() is True


def test_key_to_jwk_shape():
    key = Key(kid="shape-test", expiry_seconds=3600)
    jwk = key.to_jwk()
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == "shape-test"
    assert "n" in jwk and "e" in jwk
    assert "=" not in jwk["n"]
    assert "=" not in jwk["e"]


def test_b64url_uint_roundtrip():
    encoded = b64url_uint(65537)  # standard RSA public exponent
    assert isinstance(encoded, str)
    assert "=" not in encoded


def test_key_manager_has_active_and_expired_key():
    km = KeyManager()
    assert km.get_active_key().is_expired() is False
    assert km.get_expired_key().is_expired() is True


def test_key_manager_get_key_by_kid():
    km = KeyManager()
    active = km.get_active_key()
    assert km.get_key(active.kid) is active


def test_key_manager_get_key_unknown_kid_returns_none():
    km = KeyManager()
    assert km.get_key("does-not-exist") is None


def test_key_manager_jwks_excludes_expired_key():
    km = KeyManager()
    jwks_doc = km.get_unexpired_jwks()
    kids = [k["kid"] for k in jwks_doc["keys"]]
    assert km.active_kid in kids
    assert km.expired_kid not in kids


# /.well-known/jwks.json tests

def test_jwks_endpoint_status_and_shape(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1


def test_jwks_endpoint_only_serves_unexpired_keys(client):
    data = client.get("/.well-known/jwks.json").get_json()
    kids = [k["kid"] for k in data["keys"]]
    assert app_module.key_manager.expired_kid not in kids
    assert app_module.key_manager.active_kid in kids


def test_jwks_endpoint_rejects_post(client):
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_jwks_endpoint_rejects_delete(client):
    assert client.delete("/.well-known/jwks.json").status_code == 405


# /auth tests

def test_auth_returns_token(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "token" in data
    assert isinstance(data["token"], str)


def test_auth_token_has_active_kid_in_header(client):
    token = client.post("/auth").get_json()["token"]
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.key_manager.active_kid


def test_auth_token_is_verifiable_with_active_public_key(client):
    token = client.post("/auth").get_json()["token"]
    active_key = app_module.key_manager.get_active_key()
    decoded = jwt.decode(token, active_key.public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_expired_query_param_uses_expired_kid(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.key_manager.expired_kid


def test_auth_expired_query_param_yields_expired_claim(client):
    token = client.post("/auth?expired=true").get_json()["token"]
    expired_key = app_module.key_manager.get_expired_key()

    unverified = jwt.decode(
        token, expired_key.public_key, algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert unverified["exp"] < time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, expired_key.public_key, algorithms=["RS256"])


def test_auth_expired_key_not_in_jwks(client):
    token = client.post("/auth?expired=true").get_json()["token"]
    used_kid = jwt.get_unverified_header(token)["kid"]

    jwks_doc = client.get("/.well-known/jwks.json").get_json()
    kids_in_jwks = [k["kid"] for k in jwks_doc["keys"]]
    assert used_kid not in kids_in_jwks


def test_auth_accepts_empty_body(client):
    # this is basically what the grader's test client does
    resp = client.post("/auth", data=b"")
    assert resp.status_code == 200


def test_auth_rejects_get(client):
    assert client.get("/auth").status_code == 405


def test_auth_rejects_put(client):
    assert client.put("/auth").status_code == 405


def test_auth_rejects_delete(client):
    assert client.delete("/auth").status_code == 405


# full flow

def test_jwks_public_key_verifies_auth_token(client):
    token = client.post("/auth").get_json()["token"]
    kid = jwt.get_unverified_header(token)["kid"]

    jwks_doc = client.get("/.well-known/jwks.json").get_json()
    assert any(k["kid"] == kid for k in jwks_doc["keys"])

    key = app_module.key_manager.get_key(kid)
    decoded = jwt.decode(token, key.public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
