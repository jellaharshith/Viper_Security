CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS kb_docs (
    collection text NOT NULL,
    id text NOT NULL,
    text text NOT NULL,
    source text NOT NULL,
    url text NOT NULL,
    title text NOT NULL,
    meta jsonb NOT NULL DEFAULT '{}'::jsonb,
    embedding vector(768) NOT NULL,
    PRIMARY KEY (collection, id)
);

CREATE TABLE IF NOT EXISTS kb_registry (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active text,
    previous text,
    history jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(history) = 'array')
);
INSERT INTO kb_registry (singleton) VALUES (true) ON CONFLICT DO NOTHING;

ALTER TABLE kb_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_registry ENABLE ROW LEVEL SECURITY;
-- No policies or grants for anon/authenticated. Use a trusted server-side database role.
-- No ANN index: exact cosine search preserves recall for a few thousand documents.
-- Revisit indexing above roughly 50,000 records, measuring filtered-search recall first.
