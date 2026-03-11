"""
Tests for #834 — Startup environment variable validation.

Verifies that validate_required_env_vars() raises RuntimeError with a clear
message listing every missing variable, and that it is a no-op during tests.

Run: pytest tests/test_startup_env_validation.py -v
"""

from __future__ import annotations

import os
import sys

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_validate(monkeypatch, env: dict[str, str | None], *, is_testing: bool = False):
    """
    Call validate_required_env_vars() after patching the given env vars.

    env values of None → variable is deleted from the environment.
    is_testing=False forces non-test mode so the guard actually runs.
    """
    # Apply env overrides
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)

    # Force production mode by removing pytest markers
    if not is_testing:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    # Re-import to pick up the env changes
    import importlib
    import main as main_module
    importlib.reload(main_module)

    # Temporarily override is_testing detection
    original_sys_modules_pytest = sys.modules.get("pytest")
    if not is_testing:
        # Remove pytest from sys.modules so the guard sees "not in testing"
        sys.modules.pop("pytest", None)

    try:
        main_module.validate_required_env_vars()
    finally:
        # Restore pytest in sys.modules
        if not is_testing and original_sys_modules_pytest is not None:
            sys.modules["pytest"] = original_sys_modules_pytest

    return main_module


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidateRequiredEnvVars:
    """Unit tests for validate_required_env_vars() — fixes #834."""

    def test_all_vars_present_no_error(self, monkeypatch):
        """When all required vars are set, no exception should be raised."""
        monkeypatch.setenv("SUPABASE_URL", "https://proj.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_KEY", "service-key-value")
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "jwt-secret-value")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            # Should not raise
            main_module.validate_required_env_vars()
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_missing_supabase_url_raises(self, monkeypatch):
        """Missing SUPABASE_URL → RuntimeError mentioning the variable."""
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.setenv("SUPABASE_SERVICE_KEY", "service-key-value")
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "jwt-secret-value")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                main_module.validate_required_env_vars()
            assert "SUPABASE_URL" in str(exc_info.value)
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_missing_service_key_raises(self, monkeypatch):
        """Missing SUPABASE_SERVICE_KEY → RuntimeError mentioning the variable."""
        monkeypatch.setenv("SUPABASE_URL", "https://proj.supabase.co")
        monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "jwt-secret-value")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                main_module.validate_required_env_vars()
            assert "SUPABASE_SERVICE_KEY" in str(exc_info.value)
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_missing_jwt_secret_raises(self, monkeypatch):
        """Missing SUPABASE_JWT_SECRET → RuntimeError mentioning the variable."""
        monkeypatch.setenv("SUPABASE_URL", "https://proj.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_KEY", "service-key-value")
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                main_module.validate_required_env_vars()
            assert "SUPABASE_JWT_SECRET" in str(exc_info.value)
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_multiple_missing_vars_listed_in_error(self, monkeypatch):
        """All missing vars must be named in the error message."""
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                main_module.validate_required_env_vars()
            msg = str(exc_info.value)
            assert "SUPABASE_URL" in msg
            assert "SUPABASE_SERVICE_KEY" in msg
            assert "SUPABASE_JWT_SECRET" in msg
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_skipped_during_pytest_via_sys_modules(self, monkeypatch):
        """In a pytest run (pytest in sys.modules), validation is a no-op."""
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        # pytest IS in sys.modules (we're running under pytest right now)
        assert "pytest" in sys.modules
        # Should not raise even though all vars are missing
        main_module.validate_required_env_vars()

    def test_skipped_when_pytest_current_test_set(self, monkeypatch):
        """When PYTEST_CURRENT_TEST is set, validation is also a no-op."""
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "test_something")

        import importlib
        import main as main_module
        importlib.reload(main_module)

        # Even in "production" sys.modules, the env var short-circuits
        saved = sys.modules.pop("pytest", None)
        try:
            main_module.validate_required_env_vars()  # should not raise
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved

    def test_error_message_contains_fatal_hint(self, monkeypatch):
        """Error message must mention FATAL and advise setting the variables."""
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.setenv("SUPABASE_SERVICE_KEY", "key")
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "secret")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        import importlib
        import main as main_module
        importlib.reload(main_module)

        saved = sys.modules.pop("pytest", None)
        try:
            with pytest.raises(RuntimeError) as exc_info:
                main_module.validate_required_env_vars()
            msg = str(exc_info.value)
            assert "FATAL" in msg
            assert "signal-studio-auth" in msg
        finally:
            if saved is not None:
                sys.modules["pytest"] = saved
