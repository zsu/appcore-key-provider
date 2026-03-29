"""Secret blob provider abstractions and implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from appcore.common import exceptions as common_exceptions
from appcore.config import settings_models


@runtime_checkable
class SecretBlobProvider(Protocol):
    """Protocol for retrieving encrypted secret blobs."""

    def get_base_blob(self) -> str:
        """Return the required shared base secret blob."""
        ...

    def get_override_blob(self) -> str | None:
        """Return the optional environment-specific override blob."""
        ...


class FileSecretBlobProvider:
    """Retrieve secret blobs from files on disk."""

    def __init__(self, base_path: Path, override_path: Path) -> None:
        """Store resolved file paths for blob loading."""
        self._base_path = base_path
        self._override_path = override_path

    def get_base_blob(self) -> str:
        """Return the required base secret blob from disk."""
        return self._read_required_file(self._base_path)

    def get_override_blob(self) -> str | None:
        """Return the optional environment-specific override blob from disk."""
        if not self._override_path.exists():
            return None
        return self._override_path.read_text(encoding="utf-8").strip()

    @staticmethod
    def _read_required_file(path: Path) -> str:
        """Read and validate a required secret blob file."""
        if not path.exists():
            raise common_exceptions.KeyProviderError(
                f"Required secret blob file was not found: {path}"
            )
        return path.read_text(encoding="utf-8").strip()


class EnvVarSecretBlobProvider:
    """Retrieve secret blobs from environment variables."""

    def __init__(self, key_name: str) -> None:
        """Store the environment variable name for blob loading."""
        self._key_name = key_name

    def get_base_blob(self) -> str:
        """Return the required active-environment secret blob from the environment."""
        import os

        value = os.getenv(self._key_name)
        if value is None:
            raise common_exceptions.KeyProviderError(
                "Environment variable "
                f"{self._key_name!r} is not set for the secret blob"
            )
        return value

    def get_override_blob(self) -> str | None:
        """Return no override blob for single-key environment providers."""
        return None


class KeyringSecretBlobProvider:
    """Retrieve secret blobs from the operating system keyring."""

    def __init__(
        self,
        service_name: str,
        username: str,
        key_name: str,
    ) -> None:
        """Store keyring identifiers for blob loading."""
        self._service_name = service_name
        self._username = username
        self._key_name = key_name

    def get_base_blob(self) -> str:
        """Return the required active-environment secret blob from keyring."""
        value = self._get_password(self._key_name)
        if value is None:
            raise common_exceptions.KeyProviderError(
                "Keyring entry "
                f"{self._key_name!r} was not found in service "
                f"{self._service_name!r}"
            )
        return value

    def get_override_blob(self) -> str | None:
        """Return no override blob for single-key keyring providers."""
        return None

    def _get_password(self, key_name: str) -> str | None:
        """Read a secret blob from keyring."""
        import keyring

        return keyring.get_password(self._service_name, key_name)


class AzureKeyVaultSecretBlobProvider:
    """Retrieve secret blobs from Azure Key Vault."""

    def __init__(
        self,
        vault_url: str,
        key_name: str,
    ) -> None:
        """Create the Azure client and store secret names."""
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        self._client = SecretClient(
            vault_url=vault_url,
            credential=DefaultAzureCredential(),
        )
        self._key_name = key_name

    def get_base_blob(self) -> str:
        """Return the required active-environment secret blob from Azure Key Vault."""
        return self._get_required_secret(self._key_name)

    def get_override_blob(self) -> str | None:
        """Return no override blob for single-key Azure providers."""
        return None

    def _get_required_secret(self, secret_name: str) -> str:
        """Read a required secret blob from Azure Key Vault."""
        try:
            secret = self._client.get_secret(secret_name)
        except Exception as exc:
            raise common_exceptions.KeyProviderError(
                f"Failed to retrieve Azure secret blob {secret_name!r}: {exc}"
            ) from exc
        if secret.value is None:
            raise common_exceptions.KeyProviderError(
                f"Azure secret blob {secret_name!r} is empty"
            )
        return secret.value


class SecretBlobProviderFactory:
    """Create secret blob providers from validated settings."""

    @staticmethod
    def create(
        settings: settings_models.SecretSourceSettings,
        *,
        environment: str,
        root_dir: Path,
    ) -> SecretBlobProvider:
        """Instantiate the configured secret blob provider."""
        if settings.provider == "file":
            default_dir = root_dir / "secrets"
            base_path = settings.file.base_path or str(default_dir / "app.enc.yaml")
            override_path = settings.file.override_path or str(
                default_dir / f"app.enc.{environment}.yaml"
            )
            return FileSecretBlobProvider(Path(base_path), Path(override_path))

        if settings.provider == "env_var":
            return EnvVarSecretBlobProvider(settings.env_var.key_name)

        if settings.provider == "keyring":
            return KeyringSecretBlobProvider(
                service_name=settings.keyring.service_name,
                username=settings.keyring.username,
                key_name=settings.keyring.key_name,
            )

        if settings.provider == "azure_key_vault":
            if settings.azure_key_vault is None:
                raise ValueError("azure_key_vault settings are required")
            return AzureKeyVaultSecretBlobProvider(
                vault_url=settings.azure_key_vault.vault_url,
                key_name=settings.azure_key_vault.key_name,
            )

        raise ValueError(f"Unknown secret blob provider: {settings.provider!r}")
