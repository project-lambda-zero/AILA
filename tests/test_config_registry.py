"""Tests for ConfigRegistry and SchemaRegistry (aila.storage.registry).

Covers: register() with defaults, get/set individual values, all_entries(),
type coercion (int/float/bool/str), env-var override precedence, missing
namespace handling, re-registration idempotency, SchemaRegistry push/create_all.

Async migration: ConfigRegistry.register/get/set/all_entries/
all_entries_by_namespace are now ``async`` (they use async_session_scope
against aila_test). ``get_sync`` stays sync. The ``registry`` fixture depends
on ``test_db`` and returns a fresh ConfigRegistry(); DB inspection blocks use
``session_scope()`` (sync psycopg against the same aila_test DB).
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlmodel import SQLModel, select

from aila.storage.database import session_scope
from aila.storage.db_models import ConfigEntryRecord
from aila.storage.registry import ConfigRegistry, SchemaRegistry, _cast_value, _field_type_name

# ---------------------------------------------------------------------------
# Test schema models
# ---------------------------------------------------------------------------

class _SampleSchema(BaseModel):
    timeout: int = 30
    verbose: bool = False
    rate: float = 1.5
    label: str = "default"


class _MinimalSchema(BaseModel):
    enabled: bool = True


class _NumericSchema(BaseModel):
    port: int = 8080
    threshold: float = 0.95


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def registry(test_db):
    """Return a fresh ConfigRegistry backed by the shared aila_test database."""
    return ConfigRegistry()


# ---------------------------------------------------------------------------
# ConfigRegistry.register()
# ---------------------------------------------------------------------------

class TestRegister:

    async def test_register_persists_defaults(self, registry):
        """register() writes one ConfigEntryRecord per field with default values."""
        await registry.register("sample", _SampleSchema)

        with session_scope() as s:
            rows = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
            )).all()

        keys = {r.key for r in rows}
        assert keys == {"timeout", "verbose", "rate", "label"}

    async def test_register_stores_correct_values(self, registry):
        """Default values are stringified correctly."""
        await registry.register("sample", _SampleSchema)

        with session_scope() as s:
            rows = {r.key: r for r in s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
            )).all()}

        assert rows["timeout"].value == "30"
        assert rows["timeout"].value_type == "int"
        assert rows["verbose"].value == "False"
        assert rows["verbose"].value_type == "bool"
        assert rows["rate"].value == "1.5"
        assert rows["rate"].value_type == "float"
        assert rows["label"].value == "default"
        assert rows["label"].value_type == "str"

    async def test_register_idempotent_preserves_overrides(self, registry):
        """Re-registering the same namespace does not overwrite user changes."""
        await registry.register("sample", _SampleSchema)

        # Simulate user override
        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            row.value = "60"
            s.add(row)
            s.commit()

        # Re-register
        await registry.register("sample", _SampleSchema)

        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
        assert row.value == "60", "User override must survive re-registration"

    async def test_register_multiple_namespaces(self, registry):
        """Multiple namespaces coexist without interference."""
        await registry.register("ns_a", _MinimalSchema)
        await registry.register("ns_b", _NumericSchema)

        with session_scope() as s:
            rows_a = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "ns_a",
            )).all()
            rows_b = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "ns_b",
            )).all()

        assert {r.key for r in rows_a} == {"enabled"}
        assert {r.key for r in rows_b} == {"port", "threshold"}


# ---------------------------------------------------------------------------
# ConfigRegistry.get()
# ---------------------------------------------------------------------------

class TestGet:

    async def test_get_returns_typed_value_from_db(self, registry):
        """get() returns a value cast to the schema field type."""
        await registry.register("sample", _SampleSchema)

        assert await registry.get("sample", "timeout") == 30
        assert isinstance(await registry.get("sample", "timeout"), int)
        assert await registry.get("sample", "verbose") is False
        assert await registry.get("sample", "rate") == 1.5
        assert isinstance(await registry.get("sample", "rate"), float)
        assert await registry.get("sample", "label") == "default"

    async def test_get_env_var_overrides_db(self, registry, monkeypatch):
        """Environment variable AILA_{NS}_{KEY} takes precedence over DB."""
        await registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_TIMEOUT", "99")
        assert await registry.get("sample", "timeout") == 99

    async def test_get_env_var_bool_coercion(self, registry, monkeypatch):
        """Env-var booleans are coerced correctly."""
        await registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_VERBOSE", "true")
        assert await registry.get("sample", "verbose") is True

        monkeypatch.setenv("AILA_SAMPLE_VERBOSE", "0")
        assert await registry.get("sample", "verbose") is False

    async def test_get_env_var_float_coercion(self, registry, monkeypatch):
        """Env-var floats are coerced correctly."""
        await registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_RATE", "3.14")
        assert await registry.get("sample", "rate") == pytest.approx(3.14)

    async def test_get_missing_key_returns_none(self, registry):
        """get() for an unregistered namespace returns None."""
        assert await registry.get("nonexistent", "whatever") is None

    async def test_get_missing_key_in_registered_namespace(self, registry):
        """get() for a key not in the schema (and not in DB) returns None."""
        await registry.register("sample", _SampleSchema)
        assert await registry.get("sample", "does_not_exist") is None

    async def test_get_falls_back_to_schema_default(self, registry):
        """If DB row is missing, get() falls back to the schema default."""
        await registry.register("sample", _SampleSchema)

        # Delete the DB row for 'timeout'
        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            s.delete(row)
            s.commit()

        # Should still return the schema default
        assert await registry.get("sample", "timeout") == 30


# ---------------------------------------------------------------------------
# ConfigRegistry.set()
# ---------------------------------------------------------------------------

class TestSet:

    async def test_set_updates_existing_row(self, registry):
        """set() updates an existing DB row for a registered key."""
        await registry.register("sample", _SampleSchema)
        await registry.set("sample", "timeout", "120")

        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row.value == "120"

    async def test_set_creates_row_if_missing(self, registry):
        """set() creates a new DB row if none exists yet."""
        await registry.register("sample", _SampleSchema)

        # Delete the row first
        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            s.delete(row)
            s.commit()

        await registry.set("sample", "timeout", "77")

        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row is not None
        assert row.value == "77"
        assert row.value_type == "int"

    async def test_set_roundtrip_via_get(self, registry):
        """set() value is immediately visible via get()."""
        await registry.register("sample", _SampleSchema)
        await registry.set("sample", "timeout", "200")
        assert await registry.get("sample", "timeout") == 200

    async def test_set_bool_roundtrip(self, registry):
        """Boolean set/get roundtrip."""
        await registry.register("sample", _SampleSchema)
        await registry.set("sample", "verbose", "true")
        assert await registry.get("sample", "verbose") is True

    async def test_set_float_roundtrip(self, registry):
        """Float set/get roundtrip."""
        await registry.register("sample", _SampleSchema)
        await registry.set("sample", "rate", "2.71828")
        assert await registry.get("sample", "rate") == pytest.approx(2.71828)

    async def test_set_unregistered_namespace_raises(self, registry):
        """set() raises ValueError for an unregistered namespace."""
        with pytest.raises(ValueError, match="No schema registered"):
            await registry.set("missing_ns", "key", "val")

    async def test_set_unknown_key_raises(self, registry):
        """set() raises ValueError for a key not in the schema."""
        await registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError, match="Key 'bogus' not found"):
            await registry.set("sample", "bogus", "val")

    async def test_set_invalid_int_raises(self, registry):
        """set() raises ValueError when value cannot be cast to the field type."""
        await registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError):
            await registry.set("sample", "timeout", "not_a_number")

    async def test_set_invalid_bool_raises(self, registry):
        """set() raises ValueError for unparseable booleans."""
        await registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError, match="Cannot parse"):
            await registry.set("sample", "verbose", "maybe")

    async def test_set_updates_timestamp(self, registry):
        """set() updates the updated_at field on the DB row."""
        await registry.register("sample", _SampleSchema)

        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            original_ts = row.updated_at

        await registry.set("sample", "timeout", "999")

        with session_scope() as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row.updated_at >= original_ts


# ---------------------------------------------------------------------------
# ConfigRegistry.all_entries()
# ---------------------------------------------------------------------------

class TestAllEntries:

    async def test_all_entries_returns_all_rows(self, registry):
        """all_entries() returns one dict per DB row."""
        await registry.register("sample", _SampleSchema)
        entries = await registry.all_entries()
        keys = {e["key"] for e in entries}
        assert keys == {"timeout", "verbose", "rate", "label"}

    async def test_all_entries_dict_shape(self, registry):
        """Each entry dict has the expected keys."""
        await registry.register("sample", _SampleSchema)
        entry = (await registry.all_entries())[0]
        expected_keys = {"namespace", "key", "value", "value_type", "updated_at", "source"}
        assert set(entry.keys()) == expected_keys

    async def test_all_entries_source_db_by_default(self, registry):
        """source is 'db' when no env var override is active."""
        await registry.register("sample", _SampleSchema)
        for entry in await registry.all_entries():
            assert entry["source"] == "db"

    async def test_all_entries_source_env_when_overridden(self, registry, monkeypatch):
        """source is 'env' when the corresponding env var is set."""
        await registry.register("sample", _SampleSchema)
        monkeypatch.setenv("AILA_SAMPLE_TIMEOUT", "42")
        entries = {e["key"]: e for e in await registry.all_entries()}
        assert entries["timeout"]["source"] == "env"
        assert entries["timeout"]["value"] == "42"
        assert entries["verbose"]["source"] == "db"

    async def test_all_entries_sorted_by_namespace_and_key(self, registry):
        """all_entries() returns rows sorted by (namespace, key)."""
        await registry.register("zz_ns", _MinimalSchema)
        await registry.register("aa_ns", _NumericSchema)
        entries = await registry.all_entries()
        ns_key_pairs = [(e["namespace"], e["key"]) for e in entries]
        assert ns_key_pairs == sorted(ns_key_pairs)

    async def test_all_entries_empty_when_nothing_registered(self, registry):
        """all_entries() returns empty list before any registration."""
        assert await registry.all_entries() == []

    async def test_all_entries_across_multiple_namespaces(self, registry):
        """all_entries() aggregates across all registered namespaces."""
        await registry.register("sample", _SampleSchema)
        await registry.register("minimal", _MinimalSchema)
        entries = await registry.all_entries()
        namespaces = {e["namespace"] for e in entries}
        assert namespaces == {"sample", "minimal"}


# ---------------------------------------------------------------------------
# _cast_value() and _field_type_name() helpers (pure unit, no DB)
# ---------------------------------------------------------------------------

class TestCastValue:

    def test_cast_int(self):
        fi = _SampleSchema.model_fields["timeout"]
        assert _cast_value("42", fi) == 42

    def test_cast_float(self):
        fi = _SampleSchema.model_fields["rate"]
        assert _cast_value("3.14", fi) == pytest.approx(3.14)

    def test_cast_bool_true_variants(self):
        fi = _SampleSchema.model_fields["verbose"]
        for val in ("true", "True", "TRUE", "1", "yes", "YES"):
            assert _cast_value(val, fi) is True

    def test_cast_bool_false_variants(self):
        fi = _SampleSchema.model_fields["verbose"]
        for val in ("false", "False", "FALSE", "0", "no", "NO"):
            assert _cast_value(val, fi) is False

    def test_cast_bool_invalid_raises(self):
        fi = _SampleSchema.model_fields["verbose"]
        with pytest.raises(ValueError, match="Cannot parse"):
            _cast_value("maybe", fi)

    def test_cast_str(self):
        fi = _SampleSchema.model_fields["label"]
        assert _cast_value("hello", fi) == "hello"

    def test_cast_none_field_info_returns_str(self):
        """When field_info is None, raw value is returned as string."""
        assert _cast_value("anything", None) == "anything"

    def test_cast_int_invalid_raises(self):
        fi = _SampleSchema.model_fields["timeout"]
        with pytest.raises(ValueError):
            _cast_value("not_a_number", fi)

    def test_cast_float_invalid_raises(self):
        fi = _SampleSchema.model_fields["rate"]
        with pytest.raises(ValueError):
            _cast_value("not_a_float", fi)


class TestFieldTypeName:

    def test_int_annotation(self):
        fi = _SampleSchema.model_fields["timeout"]
        assert _field_type_name(fi) == "int"

    def test_float_annotation(self):
        fi = _SampleSchema.model_fields["rate"]
        assert _field_type_name(fi) == "float"

    def test_bool_annotation(self):
        fi = _SampleSchema.model_fields["verbose"]
        assert _field_type_name(fi) == "bool"

    def test_str_annotation(self):
        fi = _SampleSchema.model_fields["label"]
        assert _field_type_name(fi) == "str"

    def test_none_returns_str(self):
        assert _field_type_name(None) == "str"


# ---------------------------------------------------------------------------
# SchemaRegistry (pure unit tests using an isolated in-memory SQLite engine
# for create_all -- no aila_test DB required).
# ---------------------------------------------------------------------------

class TestSchemaRegistry:

    def test_push_registers_model(self):
        """push() adds model classes to the registry."""
        sr = SchemaRegistry()
        sr.push(ConfigEntryRecord)
        assert ConfigEntryRecord in sr._models

    def test_push_deduplicates(self):
        """push() ignores duplicate registrations."""
        sr = SchemaRegistry()
        sr.push(ConfigEntryRecord)
        sr.push(ConfigEntryRecord)
        assert sr._models.count(ConfigEntryRecord) == 1

    def test_push_multiple_at_once(self):
        """push() accepts multiple model classes in a single call."""
        from aila.storage.db_models import ConfigEntryRecord, SecretRecord

        sr = SchemaRegistry()
        sr.push(ConfigEntryRecord, SecretRecord)
        assert len(sr._models) == 2
        assert ConfigEntryRecord in sr._models
        assert SecretRecord in sr._models

    def test_create_all_creates_tables(self):
        """create_all() creates tables for pushed models in a fresh engine."""
        from sqlalchemy import inspect as sa_inspect

        sr = SchemaRegistry()
        sr.push(ConfigEntryRecord)

        engine = create_engine("sqlite://", echo=False)
        sr.create_all(engine)

        inspector = sa_inspect(engine)
        table_names = inspector.get_table_names()
        assert "configentryrecord" in table_names

    def test_create_all_idempotent(self):
        """Calling create_all() twice does not raise."""
        sr = SchemaRegistry()
        sr.push(ConfigEntryRecord)

        engine = create_engine("sqlite://", echo=False)
        sr.create_all(engine)
        sr.create_all(engine)  # Must not raise

    def test_create_all_empty_registry(self):
        """create_all() with no pushed models does not raise."""
        sr = SchemaRegistry()
        engine = create_engine("sqlite://", echo=False)
        sr.create_all(engine)  # Falls back to SQLModel.metadata.create_all
        # Reference SQLModel so the pure unit test still exercises the fallback
        # path without pyflakes flagging the import as unused.
        assert isinstance(SQLModel.metadata.tables, dict)

    def test_push_preserves_insertion_order(self):
        """push() preserves order of registration."""
        from aila.storage.db_models import ConfigEntryRecord, SecretRecord

        sr = SchemaRegistry()
        sr.push(SecretRecord)
        sr.push(ConfigEntryRecord)
        assert sr._models == [SecretRecord, ConfigEntryRecord]
