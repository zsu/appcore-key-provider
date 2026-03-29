# appcore-key-provider

Key provider abstractions and implementations for `appcore` applications.

## Purpose

`appcore-key-provider` resolves encryption key material from supported sources:

- environment variables
- OS keyring
- Azure Key Vault

It also supports layered lookup so local environment values can be overridden by
keyring when both are available.

For non-master application secrets, it also provides full secret-blob providers
that can load encrypted `app.enc*.yaml` payloads from:

- files on disk
- environment variables
- OS keyring
- Azure Key Vault

## Main exports

- `KeyProvider`
- `KeyProviderFactory`
- `EnvVarKeyProvider`
- `KeyringProvider`
- `AzureKeyVaultProvider`
- `LayeredKeyProvider`
- `SecretBlobProvider`
- `SecretBlobProviderFactory`
- `FileSecretBlobProvider`
- `EnvVarSecretBlobProvider`
- `KeyringSecretBlobProvider`
- `AzureKeyVaultSecretBlobProvider`

## Example

```python
from appcore.key_provider import KeyProviderFactory
from appcore.config import MasterKeySettings

provider = KeyProviderFactory.create(MasterKeySettings())
key_bytes = provider.get_key("app-encryption-key")
```

## Secret blob usage

`SecretBlobProviderFactory` is used by bootstrap to load encrypted secret
documents such as `secrets/app.enc.yaml` and `secrets/app.enc.dev.yaml`.

Default file-backed usage:

```python
from pathlib import Path

from appcore.config import SecretSourceSettings
from appcore.key_provider import SecretBlobProviderFactory

provider = SecretBlobProviderFactory.create(
    SecretSourceSettings(provider="file"),
    environment="dev",
    root_dir=Path.cwd(),
)

base_blob = provider.get_base_blob()
override_blob = provider.get_override_blob()
```

Configuration override example:

```python
from appcore.config import SecretFileSettings, SecretSourceSettings

settings = SecretSourceSettings(
    provider="file",
    file=SecretFileSettings(
        base_path="custom-secrets/shared.enc",
        override_path="custom-secrets/dev.enc",
    ),
)
```

Environment variable example:

```python
from appcore.config import SecretEnvVarSettings, SecretSourceSettings

settings = SecretSourceSettings(
    provider="env_var",
    env_var=SecretEnvVarSettings(
        key_name="APP_SECRETS",
    ),
)
```

In this model, `APP_SECRETS` contains one encrypted blob for the active environment.

Keyring example:

```python
from appcore.config import SecretKeyringSettings, SecretSourceSettings

settings = SecretSourceSettings(
    provider="keyring",
    keyring=SecretKeyringSettings(
        service_name="customer_support_ops",
        key_name="app-secrets",
    ),
)
```

In this model, the single keyring entry contains the full encrypted blob for the active environment.

Azure Key Vault example:

```python
from appcore.config import SecretAzureKeyVaultSettings, SecretSourceSettings

settings = SecretSourceSettings(
    provider="azure_key_vault",
    azure_key_vault=SecretAzureKeyVaultSettings(
        vault_url="https://example.vault.azure.net/",
        key_name="app-secrets",
    ),
)
```

In this model, the single vault secret contains the full encrypted blob for the active environment.

## Optional extras

- `keyring-provider`
- `azure-provider`

## Dependency order

This package depends on
[`appcore-config`](https://pypi.org/project/appcore-config/) and is used by
[`appcore-crypto`](https://pypi.org/project/appcore-crypto/).
