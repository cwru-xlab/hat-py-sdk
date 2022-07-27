from __future__ import annotations

import re

API_VERSION = "v2.6"
SCHEME = "https"
SCHEME_PATTERN = re.compile(r"^(?:http|https):/+")


def with_scheme(url: str) -> str:
    if SCHEME_PATTERN.match(url) is None:
        base = url
    else:
        base = SCHEME_PATTERN.split(url)[-1]
    return f"{SCHEME}://{base}"


def hat_domain(username: str) -> str:
    return with_scheme(f"{username}.hubat.net")


def username_public_key(username: str) -> str:
    return domain_public_key(hat_domain(username))


def domain_public_key(domain: str) -> str:
    return with_scheme(f"{domain}/publickey")


def username_owner_token(username: str) -> str:
    return domain_owner_token(hat_domain(username))


def domain_owner_token(domain: str) -> str:
    return with_scheme(f"{domain}/users/access_token")


def username_app_token(username: str, appname: str) -> str:
    return domain_app_token(hat_domain(username), appname)


def domain_app_token(domain: str, appname: str) -> str:
    return f"{domain_api(domain)}/applications/{appname}/access-token"


def username_api(username: str) -> str:
    return domain_api(hat_domain(username))


def domain_api(domain: str) -> str:
    return with_scheme(f"{domain}/api/{API_VERSION}")


def username_data(username: str) -> str:
    return domain_data(hat_domain(username))


def domain_data(domain: str) -> str:
    return f"{domain_api(domain)}/data"


def username_endpoint(username: str, namespace: str, endpoint: str) -> str:
    return domain_endpoint(hat_domain(username), namespace, endpoint)


def domain_endpoint(domain: str, namespace: str, endpoint: str) -> str:
    return f"{domain_data(domain)}/{namespace}/{endpoint}"
