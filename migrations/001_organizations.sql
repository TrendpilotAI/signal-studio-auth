-- ============================================================
-- Migration 001: Organizations table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.organizations (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    vertical        TEXT NOT NULL DEFAULT 'general',
    schema_name     TEXT UNIQUE,  -- tenant schema slug
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

-- Org members can read their own org
CREATE POLICY "org_members_read" ON public.organizations
    FOR SELECT
    USING (
        id = (
            (auth.jwt() -> 'app_metadata' ->> 'organization_id')::bigint
        )
    );

-- Service role bypass
CREATE POLICY "service_role_all" ON public.organizations
    FOR ALL
    USING (auth.role() = 'service_role');
