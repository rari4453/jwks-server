# JWKS Server

Project 1 - MANAN PURI (MP1038)
 RESTful JWKS server built with Flask.
Generates RSA keys, serves the public ones through a JWKS endpoint and
hands out signed JWTs through an auth endpoint including a version signed
with an already-expired key.

## Setup

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running it

```
python app.py
```

Runs on `http://localhost:8080`.

## Endpoints

- `GET /.well-known/jwks.json` - returns JWKS with only unexpired keys
- `POST /auth` - returns a valid signed JWT
- `POST /auth?expired=true` - returns a JWT signed with an expired key and an expired exp claim

## Testing

```
pytest --cov=. --cov-report=term-missing
```

## Files

- `app.py` - the Flask routes
- `keys.py` - key generation + JWKS stuff
- `test_app.py` - tests
- `requirements.txt`

Keys are just kept in memory, no persistence.
