# lyfe.ninja BlkSeal Python SDK
Lightweight Python client for signing and verifying digital content using lyfe.ninja's BlkSeal product powered by BlkBolt™.

Designed for zero dependencies, simple integration, and exact content verification.

# Overview

BlkSeal provides:
- Deterministic hashing
- Minimal, explicit canonicalization
- Content signing (authenticated)
- Content verification (public or authenticated)

# Installation
Install from github
```
pip install git+https://github.com/lyfeninja/lyfeninja_blkseal_python_sdk.git
``` 
or just clone to working directory, sometimes I think this is easier
```
git clone https://github.com/lyfeninja/lyfeninja_blkseal_python_sdk.git
```
(Coming soon via PyPI)


# Quick Start

```
import blkseal

#####################################################################
#load environment variables
#####################################################################

import os

lyfeninja_client_id = os.getenv('LYFENINJA_CLIENT_ID')
lyfeninja_client_secret = os.getenv('LYFENINJA_CLIENT_SECRET')
lyfeninja_lease_id = os.getenv('LYFENINJA_LEASE_ID')

#####################################################################
#initiate client
#####################################################################

client = blkseal.BlkSealClient(
    client_id=lyfeninja_client_id,
    client_secret=lyfeninja_client_secret,
    default_scope="sign:content verify:content",
)

#####################################################################
#get access token
#####################################################################

token = client.get_token()
print(token)

#####################################################################
# sign text
#####################################################################

#make request
response = client.sign_text(
    lease_id=lyfeninja_lease_id,
    text='Hello world!',
)

signature_b64 = response["signature_b64"]
print(signature_b64)

#####################################################################
# verify using public endpoint
#####################################################################

#make request
result = client.verify_text(
    text='Hello world!',
    signature_b64=signature_b64,
)

#print result
print(result)

#try modifying text to see how result changes
result = client.verify_text(
    text='Hello World',
    signature_b64=signature_b64x,
)

#print result
print(result)

#####################################################################
# verify using private endpoint (requires valid token)
#####################################################################

#make request
result = client.verify_text(
    text="Hello world!",
    signature_b64=signature_b64,
    private=True,
)

#print result
print(result)

#####################################################################
# sign bytes / file
#####################################################################

#open file
with open("tests.py", "rb") as f:
    file_bytes = f.read()

#make request
response = client.sign_bytes(
    lease_id=lyfeninja_lease_id,
    data=file_bytes,
)

#get signature
signature_b64 = response["signature_b64"]

#####################################################################
# verify bytes / file
#####################################################################

#open file
with open("tests.py", "rb") as f:
    file_bytes = f.read()

#make request
result = client.verify_bytes(
    data=file_bytes,
    signature_b64=signature_b64,
)

#print result
print(result)
```
