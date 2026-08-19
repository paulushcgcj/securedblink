"""Tests for securedblink vault connection resolution."""

from unittest.mock import Mock, patch

import pytest

from securedblink.vault.resolver import ConnectionResolver, get_resolver


@pytest.fixture
def vault():
    return Mock()


def test_resolve_alias_adds_vault_metadata(vault):
    vault.get.return_value = {"jdbc_url": "sqlite://", "username": "user"}
    result = ConnectionResolver.__new__(ConnectionResolver)
    result._vault = vault

    assert result.resolve(alias="prod") == {
        "jdbc_url": "sqlite://",
        "username": "user",
        "_source": "vault",
        "_alias": "prod",
    }


def test_resolve_missing_alias_raises(vault):
    vault.get.return_value = None
    resolver = ConnectionResolver.__new__(ConnectionResolver)
    resolver._vault = vault

    with pytest.raises(ValueError, match="not found"):
        resolver.resolve(alias="missing")


def test_resolve_direct_url_and_missing_input(vault):
    resolver = ConnectionResolver.__new__(ConnectionResolver)
    resolver._vault = vault

    assert resolver.resolve(url="sqlite://") == {
        "jdbc_url": "sqlite://",
        "_source": "direct",
    }
    with pytest.raises(ValueError, match="Either alias or url"):
        resolver.resolve()


def test_resolver_delegates_vault_operations(vault):
    vault.get.return_value = {"jdbc_url": "sqlite://"}
    vault.list_aliases.return_value = ["prod"]
    vault.get_metadata.return_value = {"source": "direct"}
    vault.exists.return_value = True
    resolver = ConnectionResolver.__new__(ConnectionResolver)
    resolver._vault = vault

    assert resolver.resolve_alias("prod") == {
        "jdbc_url": "sqlite://",
        "_source": "vault",
        "_alias": "prod",
    }
    assert resolver.resolve_url("sqlite://") == {
        "jdbc_url": "sqlite://",
        "_source": "direct",
    }
    assert resolver.get_all_vault_aliases() == ["prod"]
    assert resolver.get_vault_metadata("prod") == {"source": "direct"}
    assert resolver.alias_exists("prod")


def test_resolve_alias_missing_and_global_cache(vault):
    vault.get.return_value = None
    resolver = ConnectionResolver.__new__(ConnectionResolver)
    resolver._vault = vault
    with pytest.raises(ValueError, match="not found"):
        resolver.resolve_alias("missing")

    with patch("securedblink.vault.resolver.get_vault_store", return_value=vault):
        import securedblink.vault.resolver as module

        module._resolver = None
        first = get_resolver()
        assert get_resolver() is first
        module._resolver = None
