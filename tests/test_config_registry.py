"""Tests for ConfigRegistry and SchemaRegistry (aila.storage.registry).

Covers: register() with defaults, get/set individual values, all_entries(),
type coercion (int/float/bool/str), env-var override precedence, missing
namespace handling, re-registration idempotency, SchemaRegistry push/create_all.

All tests use an in-memory SQLite engine with real SQLModel sessions --
no sqlite-vec extension required.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from pydantic import BaseModel
from sqlmodel import Session, SQLModel, create_engine, select

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
def mem_engine():
    """Create an in-memory SQLite engine with ConfigEntryRecord table."""
    engine = create_engine("sqlite://", echo=False)
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture()
def _patch_session(mem_engine, monkeypatch):
    """Monkeypatch session_scope in the registry module to use the in-memory engine."""

    @contextmanager
    def _test_session_scope(settings=None):
        with Session(mem_engine) as session:
            yield session

    monkeypatch.setattr("aila.storage.registry.session_scope", _test_session_scope)


@pytest.fixture()
def registry(_patch_session):
    """Return a fresh ConfigRegistry wired to in-memory SQLite."""
    return ConfigRegistry()


# ---------------------------------------------------------------------------
# ConfigRegistry.register()
# ---------------------------------------------------------------------------

class TestRegister:

    def test_register_persists_defaults(self, registry, mem_engine):
        """register() writes one ConfigEntryRecord per field with default values."""
        registry.register("sample", _SampleSchema)

        with Session(mem_engine) as s:
            rows = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
            )).all()

        keys = {r.key for r in rows}
        assert keys == {"timeout", "verbose", "rate", "label"}

    def test_register_stores_correct_values(self, registry, mem_engine):
        """Default values are stringified correctly."""
        registry.register("sample", _SampleSchema)

        with Session(mem_engine) as s:
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

    def test_register_idempotent_preserves_overrides(self, registry, mem_engine):
        """Re-registering the same namespace does not overwrite user changes."""
        registry.register("sample", _SampleSchema)

        # Simulate user override
        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            row.value = "60"
            s.add(row)
            s.commit()

        # Re-register
        registry.register("sample", _SampleSchema)

        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
        assert row.value == "60", "User override must survive re-registration"

    def test_register_multiple_namespaces(self, registry, mem_engine):
        """Multiple namespaces coexist without interference."""
        registry.register("ns_a", _MinimalSchema)
        registry.register("ns_b", _NumericSchema)

        with Session(mem_engine) as s:
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

    def test_get_returns_typed_value_from_db(self, registry):
        """get() returns a value cast to the schema field type."""
        registry.register("sample", _SampleSchema)

        assert registry.get("sample", "timeout") == 30
        assert isinstance(registry.get("sample", "timeout"), int)
        assert registry.get("sample", "verbose") is False
        assert registry.get("sample", "rate") == 1.5
        assert isinstance(registry.get("sample", "rate"), float)
        assert registry.get("sample", "label") == "default"

    def test_get_env_var_overrides_db(self, registry, monkeypatch):
        """Environment variable AILA_{NS}_{KEY} takes precedence over DB."""
        registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_TIMEOUT", "99")
        assert registry.get("sample", "timeout") == 99

    def test_get_env_var_bool_coercion(self, registry, monkeypatch):
        """Env-var booleans are coerced correctly."""
        registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_VERBOSE", "true")
        assert registry.get("sample", "verbose") is True

        monkeypatch.setenv("AILA_SAMPLE_VERBOSE", "0")
        assert registry.get("sample", "verbose") is False

    def test_get_env_var_float_coercion(self, registry, monkeypatch):
        """Env-var floats are coerced correctly."""
        registry.register("sample", _SampleSchema)

        monkeypatch.setenv("AILA_SAMPLE_RATE", "3.14")
        assert registry.get("sample", "rate") == pytest.approx(3.14)

    def test_get_missing_key_returns_none(self, registry):
        """get() for an unregistered namespace returns None."""
        assert registry.get("nonexistent", "whatever") is None

    def test_get_missing_key_in_registered_namespace(self, registry):
        """get() for a key not in the schema (and not in DB) returns None."""
        registry.register("sample", _SampleSchema)
        assert registry.get("sample", "does_not_exist") is None

    def test_get_falls_back_to_schema_default(self, registry, mem_engine):
        """If DB row is missing, get() falls back to the schema default."""
        registry.register("sample", _SampleSchema)

        # Delete the DB row for 'timeout'
        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            s.delete(row)
            s.commit()

        # Should still return the schema default
        assert registry.get("sample", "timeout") == 30


# ---------------------------------------------------------------------------
# ConfigRegistry.set()
# ---------------------------------------------------------------------------

class TestSet:

    def test_set_updates_existing_row(self, registry, mem_engine):
        """set() updates an existing DB row for a registered key."""
        registry.register("sample", _SampleSchema)
        registry.set("sample", "timeout", "120")

        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row.value == "120"

    def test_set_creates_row_if_missing(self, registry, mem_engine):
        """set() creates a new DB row if none exists yet."""
        registry.register("sample", _SampleSchema)

        # Delete the row first
        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            s.delete(row)
            s.commit()

        registry.set("sample", "timeout", "77")

        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row is not None
        assert row.value == "77"
        assert row.value_type == "int"

    def test_set_roundtrip_via_get(self, registry):
        """set() value is immediately visible via get()."""
        registry.register("sample", _SampleSchema)
        registry.set("sample", "timeout", "200")
        assert registry.get("sample", "timeout") == 200

    def test_set_bool_roundtrip(self, registry):
        """Boolean set/get roundtrip."""
        registry.register("sample", _SampleSchema)
        registry.set("sample", "verbose", "true")
        assert registry.get("sample", "verbose") is True

    def test_set_float_roundtrip(self, registry):
        """Float set/get roundtrip."""
        registry.register("sample", _SampleSchema)
        registry.set("sample", "rate", "2.71828")
        assert registry.get("sample", "rate") == pytest.approx(2.71828)

    def test_set_unregistered_namespace_raises(self, registry):
        """set() raises ValueError for an unregistered namespace."""
        with pytest.raises(ValueError, match="No schema registered"):
            registry.set("missing_ns", "key", "val")

    def test_set_unknown_key_raises(self, registry):
        """set() raises ValueError for a key not in the schema."""
        registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError, match="Key 'bogus' not found"):
            registry.set("sample", "bogus", "val")

    def test_set_invalid_int_raises(self, registry):
        """set() raises ValueError when value cannot be cast to the field type."""
        registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError):
            registry.set("sample", "timeout", "not_a_number")

    def test_set_invalid_bool_raises(self, registry):
        """set() raises ValueError for unparseable booleans."""
        registry.register("sample", _SampleSchema)
        with pytest.raises(ValueError, match="Cannot parse"):
            registry.set("sample", "verbose", "maybe")

    def test_set_updates_timestamp(self, registry, mem_engine):
        """set() updates the updated_at field on the DB row."""
        registry.register("sample", _SampleSchema)

        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()
            original_ts = row.updated_at

        registry.set("sample", "timeout", "999")

        with Session(mem_engine) as s:
            row = s.exec(select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == "sample",
                ConfigEntryRecord.key == "timeout",
            )).first()

        assert row.updated_at >= original_ts


# ---------------------------------------------------------------------------
# ConfigRegistry.all_entries()
# ---------------------------------------------------------------------------

class TestAllEntries:

    def test_all_entries_returns_all_rows(self, registry):
        """all_entries() returns one dict per DB row."""
        registry.register("sample", _SampleSchema)
        entries = registry.all_entries()
        keys = {e["key"] for e in entries}
        assert keys == {"timeout", "verbose", "rate", "label"}

    def test_all_entries_dict_shape(self, registry):
        """Each entry dict has the expected keys."""
        registry.register("sample", _SampleSchema)
        entry = registry.all_entries()[0]
        expected_keys = {"namespace", "key", "value", "value_type", "updated_at", "source"}
        assert set(entry.keys()) == expected_keys

    def test_all_entries_source_db_by_default(self, registry):
        """source is 'db' when no env var override is active."""
        registry.register("sample", _SampleSchema)
        for entry in registry.all_entries():
            assert entry["source"] == "db"

    def test_all_entries_source_env_when_overridden(self, registry, monkeypatch):
        """source is 'env' when the corresponding env var is set."""
        registry.register("sample", _SampleSchema)
        monkeypatch.setenv("AILA_SAMPLE_TIMEOUT", "42")
        entries = {e["key"]: e for e in registry.all_entries()}
        assert entries["timeout"]["source"] == "env"
        assert entries["timeout"]["value"] == "42"
        assert entries["verbose"]["source"] == "db"

    def test_all_entries_sorted_by_namespace_and_key(self, registry):
        """all_entries() returns rows sorted by (namespace, key)."""
        registry.register("zz_ns", _MinimalSchema)
        registry.register("aa_ns", _NumericSchema)
        entries = registry.all_entries()
        ns_key_pairs = [(e["namespace"], e["key"]) for e in entries]
        assert ns_key_pairs == sorted(ns_key_pairs)

    def test_all_entries_empty_when_nothing_registered(self, registry):
        """all_entries() returns empty list before any registration."""
        assert registry.all_entries() == []

    def test_all_entries_across_multiple_namespaces(self, registry):
        """all_entries() aggregates across all registered namespaces."""
        registry.register("sample", _SampleSchema)
        registry.register("minimal", _MinimalSchema)
        entries = registry.all_entries()
        namespaces = {e["namespace"] for e in entries}
        assert namespaces == {"sample", "minimal"}


# ---------------------------------------------------------------------------
# _cast_value() and _field_type_name() helpers
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
# SchemaRegistry
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

    def test_push_preserves_insertion_order(self):
        """push() preserves order of registration."""
        from aila.storage.db_models import ConfigEntryRecord, SecretRecord

        sr = SchemaRegistry()
        sr.push(SecretRecord)
        sr.push(ConfigEntryRecord)
        assert sr._models == [SecretRecord, ConfigEntryRecord]
