-- Run on first container start by docker-entrypoint-initdb.d.
-- Idempotent: only fires when the data volume is empty.
--
-- AILA uses pgvector for embedding storage (KnowledgeEntryRecord and others).
-- The pgvector/pgvector image already has the extension files installed; this
-- enables it inside the `aila` database.

\connect aila
CREATE EXTENSION IF NOT EXISTS vector;
