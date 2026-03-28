"""Acceptance tests for key provider implementations."""

from __future__ import annotations

import sys
import types

import pytest

from appcore.common import KeyProviderError
from appcore.config import (
    AzureKeyVaultSettings,
    EnvVarSettings,
    KeyringSettings,
    SecuritySettings,
)
from appcore.key_provider import (
    AzureKeyVaultProvider,
    EnvVarKeyProvider,
    KeyProviderFactory,
    KeyringProvider,
    LayeredKeyProvider,
)


def test_k1_keyring_provider_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """K1: KeyringProvider returns UTF-8 bytes when the key exists."""
    module = types.SimpleNamespace(get_password=lambda service, key: "secret-value")
    monkeypatch.setitem(sys.modules, "keyring", module)
    provider = KeyringProvider("svc", "user")
    assert provider.get_key("name") == b"secret-value"


def test_k2_keyring_provider_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """K2: KeyringProvider raises when the key does not exist."""
    module = types.SimpleNamespace(get_password=lambda service, key: None)
    monkeypatch.setitem(sys.modules, "keyring", module)
    provider = KeyringProvider("svc", "user")
    with pytest.raises(KeyProviderError):
        provider.get_key("name")


def test_k3_env_var_provider_returns_encoded_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """K3: EnvVarKeyProvider encodes the configured environment variable."""
    monkeypatch.setenv("APP_KEY", "abc123")
    provider = EnvVarKeyProvider("APP_KEY")
    assert provider.get_key("ignored") == b"abc123"


def test_k4_env_var_provider_raises_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """K4: EnvVarKeyProvider raises when the variable is missing."""
    monkeypatch.delenv("APP_KEY", raising=False)
    provider = EnvVarKeyProvider("APP_KEY")
    with pytest.raises(KeyProviderError):
        provider.get_key("ignored")


def test_k5_factory_returns_layered_provider_for_keyring() -> None:
    """K5: Factory resolves the layered env/keyring provider."""
    settings = SecuritySettings(
        key_provider="keyring",
        keyring=KeyringSettings(service_name="svc", username="user"),
    )
    assert isinstance(KeyProviderFactory.create(settings), LayeredKeyProvider)


def test_k6_factory_raises_for_unknown_provider() -> None:
    """K6: Factory rejects unsupported provider names."""
    settings = SecuritySettings.model_construct(  # type: ignore[call-arg]
        key_provider="unknown",
        keyring=KeyringSettings(),
        azure_key_vault=None,
        env_var=EnvVarSettings(),
    )
    with pytest.raises(ValueError, match="Unknown key_provider"):
        KeyProviderFactory.create(settings)


def test_k7_azure_key_vault_provider_returns_secret_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """K7: AzureKeyVaultProvider returns secret bytes from a mocked client."""

    class FakeCredential:
        """Stand-in for DefaultAzureCredential."""

    class FakeSecret:
        """Stand-in for a Key Vault secret value."""

        def __init__(self, value: str) -> None:
            """Store the fake secret value."""
            self.value = value

    class FakeSecretClient:
        """Stand-in for SecretClient."""

        def __init__(self, vault_url: str, credential: object) -> None:
            """Validate constructor arguments from the provider."""
            self.vault_url = vault_url
            self.credential = credential

        def get_secret(self, key_name: str) -> FakeSecret:
            """Return a fake secret."""
            assert key_name == "app-key"
            return FakeSecret("from-vault")

    azure_identity = types.ModuleType("azure.identity")
    azure_identity.DefaultAzureCredential = FakeCredential
    azure_secrets = types.ModuleType("azure.keyvault.secrets")
    azure_secrets.SecretClient = FakeSecretClient
    monkeypatch.setitem(sys.modules, "azure.identity", azure_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", azure_secrets)

    provider = AzureKeyVaultProvider("https://vault")
    assert provider.get_key("app-key") == b"from-vault"

    settings = SecuritySettings(
        key_provider="azure_key_vault",
        azure_key_vault=AzureKeyVaultSettings(vault_url="https://vault"),
    )
    assert isinstance(KeyProviderFactory.create(settings), AzureKeyVaultProvider)


def test_layered_provider_prefers_keyring_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keyring values override environment values when both are present."""
    monkeypatch.setenv("APP_KEY", "env-value")
    module = types.SimpleNamespace(get_password=lambda service, key: "keyring-value")
    monkeypatch.setitem(sys.modules, "keyring", module)

    provider = LayeredKeyProvider(
        [
            EnvVarKeyProvider("APP_KEY"),
            KeyringProvider("svc", "user"),
        ]
    )

    assert provider.get_key("name") == b"keyring-value"
