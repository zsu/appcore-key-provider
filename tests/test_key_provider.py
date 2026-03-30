"""Acceptance tests for key provider implementations."""

from __future__ import annotations

import sys
import types
import uuid
from pathlib import Path

import pytest
from appcore.common import KeyProviderError
from appcore.config import (
    AzureKeyVaultSettings,
    EnvVarSettings,
    KeyringSettings,
    MasterKeySettings,
    SecretAzureKeyVaultSettings,
    SecretSourceSettings,
)
from appcore.key_provider import (
    AzureKeyVaultProvider,
    AzureKeyVaultSecretBlobProvider,
    EnvVarKeyProvider,
    EnvVarSecretBlobProvider,
    FileSecretBlobProvider,
    KeyProviderFactory,
    KeyringProvider,
    KeyringSecretBlobProvider,
    LayeredKeyProvider,
    SecretBlobProviderFactory,
)


@pytest.fixture
def workspace_dir() -> Path:
    """Create a temporary workspace-local directory for provider tests."""
    directory = Path.cwd() / ".test-work" / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def test_k1_keyring_provider_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """K1: KeyringProvider returns UTF-8 bytes when the key exists."""
    module = types.SimpleNamespace(get_password=lambda service, key: "secret-value")
    monkeypatch.setitem(sys.modules, "keyring", module)
    provider = KeyringProvider("svc", "entry")
    assert provider.get_key() == b"secret-value"


def test_k2_keyring_provider_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """K2: KeyringProvider raises when the key does not exist."""
    module = types.SimpleNamespace(get_password=lambda service, key: None)
    monkeypatch.setitem(sys.modules, "keyring", module)
    provider = KeyringProvider("svc", "entry")
    with pytest.raises(KeyProviderError):
        provider.get_key()


def test_k3_env_var_provider_returns_encoded_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """K3: EnvVarKeyProvider encodes the configured environment variable."""
    monkeypatch.setenv("APP_KEY", "abc123")
    provider = EnvVarKeyProvider("APP_KEY")
    assert provider.get_key() == b"abc123"


def test_k4_env_var_provider_raises_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """K4: EnvVarKeyProvider raises when the variable is missing."""
    monkeypatch.delenv("APP_KEY", raising=False)
    provider = EnvVarKeyProvider("APP_KEY")
    with pytest.raises(KeyProviderError):
        provider.get_key()


def test_k5_factory_returns_layered_provider_for_keyring() -> None:
    """K5: Factory resolves the layered env/keyring provider."""
    settings = MasterKeySettings(
        provider="keyring",
        keyring=KeyringSettings(service_name="svc", entry_name="entry"),
    )
    assert isinstance(KeyProviderFactory.create(settings), LayeredKeyProvider)


def test_k6_factory_raises_for_unknown_provider() -> None:
    """K6: Factory rejects unsupported provider names."""
    settings = MasterKeySettings.model_construct(  # type: ignore[call-arg]
        provider="unknown",
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
            assert key_name == "app-secret"
            return FakeSecret("from-vault")

    azure_identity = types.ModuleType("azure.identity")
    azure_identity.DefaultAzureCredential = FakeCredential
    azure_secrets = types.ModuleType("azure.keyvault.secrets")
    azure_secrets.SecretClient = FakeSecretClient
    monkeypatch.setitem(sys.modules, "azure.identity", azure_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", azure_secrets)

    provider = AzureKeyVaultProvider("https://vault", "app-secret")
    assert provider.get_key() == b"from-vault"

    settings = MasterKeySettings(
        provider="azure_key_vault",
        azure_key_vault=AzureKeyVaultSettings(
            vault_url="https://vault",
            secret_name="app-secret",
        ),
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
            KeyringProvider("svc", "entry"),
        ]
    )

    assert provider.get_key() == b"keyring-value"


def test_keyring_provider_uses_configured_entry_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keyring lookups use the configured entry name rather than a call-time key."""
    calls: list[tuple[str, str]] = []

    def get_password(service: str, key: str) -> str:
        calls.append((service, key))
        return "secret-value"

    module = types.SimpleNamespace(get_password=get_password)
    monkeypatch.setitem(sys.modules, "keyring", module)

    provider = KeyringProvider("svc", "configured-entry")
    provider.get_key()

    assert calls == [("svc", "configured-entry")]


def test_file_secret_blob_provider_uses_default_paths(workspace_dir: Path) -> None:
    """File secret blob provider reads base and override files from disk."""
    secrets_dir = workspace_dir / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "app.enc.yaml").write_text("base-secret", encoding="utf-8")
    (secrets_dir / "app.enc.dev.yaml").write_text("override-secret", encoding="utf-8")

    provider = SecretBlobProviderFactory.create(
        SecretSourceSettings(provider="file"),
        environment="dev",
        root_dir=workspace_dir,
    )

    assert isinstance(provider, FileSecretBlobProvider)
    assert provider.get_base_blob() == "base-secret"
    assert provider.get_override_blob() == "override-secret"


def test_env_secret_blob_provider_reads_configured_variables(
    monkeypatch: pytest.MonkeyPatch,
    workspace_dir: Path,
) -> None:
    """Environment secret blob provider reads one configured active-environment blob."""
    monkeypatch.setenv("APP_SECRETS", "active-secret")

    provider = SecretBlobProviderFactory.create(
        SecretSourceSettings(provider="env_var"),
        environment="dev",
        root_dir=workspace_dir,
    )

    assert isinstance(provider, EnvVarSecretBlobProvider)
    assert provider.get_base_blob() == "active-secret"
    assert provider.get_override_blob() is None


def test_keyring_secret_blob_provider_reads_keyring(
    monkeypatch: pytest.MonkeyPatch,
    workspace_dir: Path,
) -> None:
    """Keyring secret blob provider reads one configured active-environment entry."""
    module = types.SimpleNamespace(
        get_password=lambda service, key: {
            "app-secrets": "active-secret",
        }.get(key)
    )
    monkeypatch.setitem(sys.modules, "keyring", module)

    provider = SecretBlobProviderFactory.create(
        SecretSourceSettings(provider="keyring"),
        environment="dev",
        root_dir=workspace_dir,
    )

    assert isinstance(provider, KeyringSecretBlobProvider)
    assert provider.get_base_blob() == "active-secret"
    assert provider.get_override_blob() is None


def test_azure_secret_blob_provider_reads_secret_names(
    monkeypatch: pytest.MonkeyPatch,
    workspace_dir: Path,
) -> None:
    """Azure secret blob provider reads one configured active-environment blob secret."""

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
            """Store constructor arguments."""
            self.vault_url = vault_url
            self.credential = credential

        def get_secret(self, secret_name: str) -> FakeSecret:
            """Return a fake blob secret."""
            secrets = {
                "app-secrets": "active-secret",
            }
            return FakeSecret(secrets[secret_name])

    azure_identity = types.ModuleType("azure.identity")
    azure_identity.DefaultAzureCredential = FakeCredential
    azure_secrets = types.ModuleType("azure.keyvault.secrets")
    azure_secrets.SecretClient = FakeSecretClient
    monkeypatch.setitem(sys.modules, "azure.identity", azure_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", azure_secrets)

    provider = SecretBlobProviderFactory.create(
        SecretSourceSettings(
            provider="azure_key_vault",
            azure_key_vault=SecretAzureKeyVaultSettings(vault_url="https://vault"),
        ),
        environment="dev",
        root_dir=workspace_dir,
    )

    assert isinstance(provider, AzureKeyVaultSecretBlobProvider)
    assert provider.get_base_blob() == "active-secret"
    assert provider.get_override_blob() is None
