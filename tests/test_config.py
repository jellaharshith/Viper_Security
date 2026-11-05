from pydantic import SecretStr

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
