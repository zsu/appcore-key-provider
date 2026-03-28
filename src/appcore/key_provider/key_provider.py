"""Key-provider abstractions and concrete implementations."""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from appcore.common import exceptions as common_exceptions
from appcore.config import settings_models


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for retrieving raw cryptographic key material."""

    def get_key(self, key_name: str) -> bytes:
        """Return raw key bytes for the requested key name."""
        ...


class KeyringProvider:
    """Retrieve keys from the operating system keyring."""

    def __init__(self, service_name: str, username: str) -> None:
        """Store keyring lookup parameters."""
        self._service_name = service_name
        self._username = username

    def get_key(self, key_name: str) -> bytes:
        """Return the requested key bytes from keyring."""
        import keyring

        value = keyring.get_password(self._service_name, key_name)
        if value is None:
            raise common_exceptions.KeyProviderError(
                f"Key {key_name!r} was not found in keyring service {self._service_name!r}"
            )
        return value.encode("utf-8")


class AzureKeyVaultProvider:
    """Retrieve keys from Azure Key Vault using default Azure credentials."""

    def __init__(self, vault_url: str) -> None:
        """Create the Azure Key Vault client."""
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        self._client = SecretClient(
            vault_url=vault_url,
            credential=DefaultAzureCredential(),
        )

    def get_key(self, key_name: str) -> bytes:
        """Return the requested key bytes from Azure Key Vault."""
        try:
            secret = self._client.get_secret(key_name)
        except Exception as exc:  # pragma: no cover - exercised via tests
            raise common_exceptions.KeyProviderError(
                f"Failed to retrieve Azure secret {key_name!r}: {exc}"
            ) from exc

        if secret.value is None:
            raise common_exceptions.KeyProviderError(f"Azure secret {key_name!r} is empty")
        return secret.value.encode("utf-8")


class EnvVarKeyProvider:
    """Retrieve keys from a single environment variable."""

    def __init__(self, env_var_name: str) -> None:
        """Store the environment variable name."""
        self._env_var_name = env_var_name

    def get_key(self, key_name: str) -> bytes:
        """Return the configured environment variable value as UTF-8 bytes."""
        value = os.getenv(self._env_var_name)
        if value is None:
            raise common_exceptions.KeyProviderError(
                f"Environment variable {self._env_var_name!r} is not set for key {key_name!r}"
            )
        return value.encode("utf-8")


class LayeredKeyProvider:
    """Retrieve a key from multiple providers with later providers overriding earlier ones."""

    def __init__(self, providers: list[KeyProvider]) -> None:
        """Store providers in evaluation order."""
        self._providers = providers

    def get_key(self, key_name: str) -> bytes:
        """Return the highest-priority available key for the given name."""
        resolved_key: bytes | None = None
        last_error: common_exceptions.KeyProviderError | None = None
        for provider in self._providers:
            try:
                resolved_key = provider.get_key(key_name)
            except common_exceptions.KeyProviderError as exc:
                last_error = exc
        if resolved_key is None:
            if last_error is not None:
                raise last_error
            raise common_exceptions.KeyProviderError(
                f"No key providers were configured for key {key_name!r}"
            )
        return resolved_key


class KeyProviderFactory:
    """Create key provider instances from validated security settings."""

    @staticmethod
    def create(settings: settings_models.SecuritySettings) -> KeyProvider:
        """Instantiate the configured key provider."""
        if settings.key_provider == "keyring":
            return LayeredKeyProvider(
                [
                    EnvVarKeyProvider(settings.env_var.env_var_name),
                    KeyringProvider(
                        service_name=settings.keyring.service_name,
                        username=settings.keyring.username,
                    ),
                ]
            )
        if settings.key_provider == "azure_key_vault":
            if settings.azure_key_vault is None:
                raise ValueError("azure_key_vault settings are required")
            return AzureKeyVaultProvider(settings.azure_key_vault.vault_url)
        if settings.key_provider == "env_var":
            return EnvVarKeyProvider(settings.env_var.env_var_name)
        raise ValueError(f"Unknown key_provider: {settings.key_provider!r}")
