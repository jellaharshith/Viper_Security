import pytest
from pydantic import SecretStr, ValidationError

from viper.config import Settings


def test_defaults_load_without_env_file() -> None:
    s = Settings(_env_file=None)
    assert s.app_env == "dev"
    assert s.log_level == "INFO"


def test_env_override(monkeypatch) -> None:
    monkeypatch.setenv("VIPER_LOG_LEVEL", "DEBUG")
    assert Settings(_env_file=None).log_level == "DEBUG"


def test_redacted_masks_secretstr() -> None:
    class WithSecret(Settings):
        api_token: SecretStr = SecretStr("super-secret")  # noqa: S105 (fake test value)

    out = WithSecret(_env_file=None).redacted()
    assert out["api_token"] == "***"  # noqa: S105
    assert "super-secret" not in str(out)


def test_pgvector_settings_are_secret(monkeypatch) -> None:
    url = "postgresql://fixture:fake-password@localhost/fixture"
    monkeypatch.setenv("VIPER_DATABASE_URL", url)
    monkeypatch.setenv("VIPER_STORE", "pgvector")
    settings = Settings(_env_file=None)
    assert settings.store == "pgvector"
    assert settings.database_url.get_secret_value() == url
    assert settings.redacted()["database_url"] == "***"
    for rendered in (repr(settings), str(settings), str(settings.redacted()), settings.model_dump_json()):
        assert url not in rendered
        assert "fake-password" not in rendered


def test_store_default_and_validation(monkeypatch) -> None:
    monkeypatch.delenv("VIPER_STORE", raising=False)
    assert Settings(_env_file=None).store == "qdrant"
    monkeypatch.setenv("VIPER_STORE", "unsupported")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
