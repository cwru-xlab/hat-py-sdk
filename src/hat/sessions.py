import datetime
import mimetypes

from . import errors, urls

_NEVER_CACHE = 0
DEFAULTS = {
    "headers": {"Content-Type": mimetypes.types_map[".json"]},
    "stream": True,
    "allowed_codes": [200] + list(errors.possible_codes),
    "allowed_methods": ["GET", "POST"],
    "stale_if_error": True,
    "expire_after": datetime.timedelta(minutes=10),
    "urls_expire_after": {
        urls.domain_owner_token("*"): _NEVER_CACHE,
        urls.domain_app_token("*", "*"): _NEVER_CACHE}}
