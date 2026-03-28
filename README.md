# appcore-key-provider

Key provider abstractions and implementations for `appcore` applications.

## Purpose

`appcore-key-provider` resolves encryption key material from supported sources:

- environment variables
- OS keyring
- Azure Key Vault

It also supports layered lookup so local environment values can be overridden by
keyring when both are available.

## Main exports

- `KeyProvider`
- `KeyProviderFactory`
- `EnvVarKeyProvider`
- `KeyringProvider`
- `AzureKeyVaultProvider`
- `LayeredKeyProvider`

## Example

```python
from appcore.key_provider import KeyProviderFactory
from appcore.config import SecuritySettings

provider = KeyProviderFactory.create(SecuritySettings())
key_bytes = provider.get_key("app-encryption-key")
```

## Optional extras

- `keyring-provider`
- `azure-provider`

## Dependency order

This package depends on
[`appcore-config`](https://pypi.org/project/appcore-config/) and is used by
[`appcore-crypto`](https://pypi.org/project/appcore-crypto/).
