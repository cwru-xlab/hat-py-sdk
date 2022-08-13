from __future__ import annotations

import re


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


def username_app_token(username: str, app_id: str) -> str:
    return domain_app_token(hat_domain(username), app_id)


def domain_app_token(domain: str, app_id: str) -> str:
    return f"{domain_api(domain)}/applications/{app_id}/access-token"


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


def no_scheme(pattern: str) -> re.Pattern:
    return re.compile(rf".*{SCHEME_PATTERN.split(pattern)[-1]}$")


def is_pk_endpoint(url: str) -> bool:
    return matched(url, PK_PATTERN)


def is_auth_endpoint(url: str) -> bool:
    return is_pk_endpoint(url) or is_token_endpoint(url)


def is_token_endpoint(url: str) -> bool:
    return matched(url, OWNER_TOKEN_PATTERN, APP_TOKEN_PATTERN)


def is_api_endpoint(url: str) -> bool:
    return matched(url, DATA_PATTERN, ENDPOINT_PATTERN)


def matched(url: str, *patterns: re.Pattern) -> bool:
    return any(p.match(url) is not None for p in patterns)


API_VERSION = "v2.6"
SCHEME = "https"

SCHEME_PATTERN = re.compile(r"^(?:http|https):/+")
PK_PATTERN = no_scheme(username_public_key(r"\w+"))
OWNER_TOKEN_PATTERN = no_scheme(username_owner_token(r"\w+"))
APP_TOKEN_PATTERN = no_scheme(username_app_token(r"\w+", r"\w+"))
ENDPOINT_PATTERN = no_scheme(username_endpoint(r"\w+", r"\w+", r"\w+"))
DATA_PATTERN = no_scheme(username_data(r"\w+"))
