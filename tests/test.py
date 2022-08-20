import asyncio

from keyring.credentials import SimpleCredential
from pydantic import BaseSettings

from hat.aioclient import AsyncActiveHatModel
from hat.aioclient import AsyncCredentialOwnerToken
from hat.aioclient import AsyncHatClient
from hat.aioclient import AsyncHttpClient
from hat.aioclient import set_async_client
from hat.client import ActiveHatModel
from hat.client import CredentialOwnerToken
from hat.client import HatClient
from hat.client import HttpClient
from hat.client import set_client
from hat.model import HatModel


# TODO Add formal unit testing


class HatEnv(BaseSettings):
    username: str
    password: str
    namespace: str
    endpoint: str

    class Config(BaseSettings.Config):
        env_file = ".env"


env = HatEnv()

credential = SimpleCredential(env.username, env.password)
namespace = env.namespace
endpoint = env.endpoint


class Person(HatModel):
    name: str = "Steve"
    age: int = 35


class ActivePerson(Person, ActiveHatModel):
    pass


class AsyncActivePerson(Person, AsyncActiveHatModel):
    pass


def sync_test():
    http_client = HttpClient()
    token = CredentialOwnerToken(http_client, credential)
    client = HatClient(http_client, token, namespace)
    set_client(client)
    exists = client.get(endpoint)
    client.delete(exists)
    p = Person(endpoint=endpoint)
    p = client.post(p)[0]
    p = client.put(p)[0]
    client.delete(p)
    p = ActivePerson()
    p = p.save(endpoint)
    p.delete()


async def async_test():
    http_client = AsyncHttpClient()
    token = AsyncCredentialOwnerToken(http_client, credential)
    client = AsyncHatClient(http_client, token, namespace)
    set_async_client(client)
    exists = await client.get(endpoint)
    await client.delete(exists)
    p = Person(endpoint=endpoint)
    p = (await client.post(p))[0]
    p = (await client.put(p))[0]
    await client.delete(p)
    p = AsyncActivePerson()
    p = await p.save(endpoint)
    await p.delete()


if __name__ == "__main__":
    sync_test()
    asyncio.run(async_test())
