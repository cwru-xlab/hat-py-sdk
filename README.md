# hat-py-sdk

Python [Dataswift HAT SDK](https://api.dataswift.io/).

## Supported endpoints

- Authentication
- Direct Data API
    - CRUD Operations
        - `POST` (one and many records)
        - `GET`
        - `PUT` (one and many records)
        - `DELETE` (one and many records)

## Usage

### Creating a client

```python
from keyring.credentials import SimpleCredential

from hat import HatClient

client = HatClient(
    # Supports any keyring Credential implementation...
    credential=SimpleCredential("username", "password"),
    # ...or saved username-based keyring credentials.
    username=None,
    # Optionally provide an existing requests.Session to reuse.
    session=None)
```

### Authentication

A [`HatClient`](https://github.com/Blockcert-CWRU/hat-py-sdk/blob/main/hat/client.py)
instance performs authentication during instantiation, so it can be used
immediately. However, the client can be re-authenticated as well:

```python
# Internally updates the client authentication token.
client.authenticate()
```

### CRUD API

All CRUD API requests use
the [`Record`](https://github.com/Blockcert-CWRU/hat-py-sdk/blob/main/hat/models.py)
class, which uses [pydantic](https://github.com/samuelcolvin/pydantic/) for
powerful data parsing and validation.

```python
from hat import Record

# GET requests can use a Record object...
records = client.get(Record(endpoint="namespace/endpoint"), ...)
# ...or just specify the endpoints.
records = client.get("namespace/endpoint", ...)

# Records are grouped by endpoint for efficient mixed-endpoint POST requests. 
records = client.post(Record(endpoint="namespace/endpoint", data={...}), ...)

records = client.put(Record(endpoint="namespace/endpoint", data={...}), ...)

# Similar to GET requests, DELETE requests can specify a Record object...
client.delete(Record(record_id="record_id"), ...)
# ...or just the record IDs.
client.delete("record_id", ...)
```