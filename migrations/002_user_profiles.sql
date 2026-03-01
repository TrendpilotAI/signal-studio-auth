-- ============================================================
-- Migration 002: User profiles table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.user_profiles (
    id                  UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email               TEXT NOT NULL,
    username            TEXT,
    first_name          TEXT DEFAULT '',
    last_name           TEXT DEFAULT '',
    organization_id     BIGINT REFERENCES public.organizations(id),
    role                TEXT NOT NULL DEFAULT 'viewer',
    legacy_user_id      INTEGER,  -- ForwardLane user ID for migration
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_org ON public.user_profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_profiles_legacy ON public.user_profiles(legacy_user_id);

-- RLS
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

-- Users can read their own profile
CREATE POLICY "users_read_own" ON public.user_profiles
    FOR SELECT
    USING (id = auth.uid());

-- Users can update their own profile
CREATE POLICY "users_update_own" ON public.user_profiles
    FOR UPDATE
    USING (id = auth.uid());

-- Org members can see other members in same org
CREATE POLICY "org_members_read" ON public.user_profiles
    FOR SELECT
    USING (
        organization_id = (
            (auth.jwt() -> 'app_metadata' ->> 'organization_id')::bigint
        )
    );

-- Service role bypass
CREATE POLICY "service_role_all" ON public.user_profiles
    FOR ALL
    USING (auth.role() = 'service_role');

-- ============================================================
-- Trigger: auto-create profile on signup
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_profiles (id, email, first_name, last_name, organization_id, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data ->> 'first_name', ''),
        COALESCE(NEW.raw_user_meta_data ->> 'last_name', ''),
        (NEW.raw_app_meta_data ->> 'organization_id')::bigint,
        COALESCE(NEW.raw_app_meta_data ->> 'role', 'viewer')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();
