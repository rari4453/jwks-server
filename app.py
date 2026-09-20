import time

import jwt
from flask import Flask, jsonify, request

from keys import KeyManager

app = Flask(__name__)
key_manager = KeyManager()


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    return jsonify(key_manager.get_unexpired_jwks()), 200


@app.route("/.well-known/jwks.json", methods=["POST", "PUT", "DELETE", "PATCH"])
def jwks_method_not_allowed():
    return jsonify({"error": "method not allowed"}), 405


@app.route("/auth", methods=["POST"])
def auth():
    # no real auth here, just mocking it like the assignment says
    use_expired = "expired" in request.args

    if use_expired:
        signing_key = key_manager.get_expired_key()
        issued_at = int(time.time()) - 7200
        expires_at = issued_at + 60  # already in the past
    else:
        signing_key = key_manager.get_active_key()
        issued_at = int(time.time())
        expires_at = issued_at + 3600

    payload = {"sub": "fake-user", "iat": issued_at, "exp": expires_at}
    token = jwt.encode(
        payload, signing_key.private_key, algorithm="RS256",
        headers={"kid": signing_key.kid},
    )

    return jsonify({"token": token}), 200


@app.route("/auth", methods=["GET", "PUT", "DELETE", "PATCH"])
def auth_method_not_allowed():
    return jsonify({"error": "method not allowed"}), 405


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
