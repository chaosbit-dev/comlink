"""Shared fixtures."""

from __future__ import annotations

import os

import pytest

from comlink.config import ComlinkSettings


@pytest.fixture(autouse=True)
def _clean_comlink_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ambient COMLINK_* env vars from leaking into unit tests."""
    for key in list(os.environ):
        if key.startswith("COMLINK_"):
            monkeypatch.delenv(key, raising=False)


def make_settings(**overrides: object) -> ComlinkSettings:
    """Settings with sane unit-test defaults (never touches a real Bridge)."""
    values: dict[str, object] = {
        "username": "tester@example.com",
        "password": "bridge-app-password",
        "tls_mode": "no-verify",
    }
    values.update(overrides)
    return ComlinkSettings.model_validate(values)
