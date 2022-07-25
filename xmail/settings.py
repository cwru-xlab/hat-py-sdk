from keyring.credentials import Credential
from pydantic import BaseSettings, SecretStr


class Settings(BaseSettings):
    hat_username: str
    hat_password: SecretStr
    hat_namespace: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @property
    def hat_credential(self) -> Credential:
        return HatCredential(self)


class HatCredential(Credential):
    __slots__ = "_settings"

    def __init__(self, settings: Settings):
        self._settings = settings

    @property
    def username(self):
        return self._settings.hat_username

    @property
    def password(self):
        return self._settings.hat_password.get_secret_value()


config = Settings()
