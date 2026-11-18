-- PhantomNet cloud console schema (Supabase / Postgres).
--
-- The console API talks to these tables with the service-role key, server
-- side only, and enforces ownership in code. Row Level Security is enabled on
-- every table with NO policies for anon/authenticated roles, so the public
-- anon key can never read or write console data directly.

create extension if not exists pgcrypto;

create table if not exists public.sensors (
    id              uuid primary key default gen_random_uuid(),
    owner_id        uuid not null references auth.users(id) on delete cascade,
    name            text not null check (name ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    created_at      timestamptz not null default now(),
    -- one-time enrollment code (hash only), valid until enroll_expires_at
    enroll_code_hash text,
    enroll_expires_at timestamptz,
    -- long-lived sensor credential (hash only), issued at enrollment
    token_hash      text unique,
    enrolled_at     timestamptz,
    last_seen       timestamptz,
    status          jsonb not null default '{}'::jsonb,
    unique (owner_id, name)
);
create index if not exists sensors_owner_idx on public.sensors(owner_id);

create table if not exists public.sensor_config (
    sensor_id   uuid primary key references public.sensors(id) on delete cascade,
    config      jsonb not null default '{}'::jsonb,
    version     integer not null default 1,
    updated_at  timestamptz not null default now()
);

create table if not exists public.incidents (
    id          bigserial primary key,
    sensor_id   uuid not null references public.sensors(id) on delete cascade,
    local_id    integer not null,
    source_ip   text not null,
    severity    text not null check (severity in ('low','medium','high')),
    score       integer not null,
    flags       jsonb not null default '[]'::jsonb,
    services    jsonb not null default '[]'::jsonb,
    event_count integer not null default 0,
    first_seen  timestamptz not null,
    last_seen   timestamptz not null,
    summary     text,
    findings    jsonb not null default '[]'::jsonb,
    guidance    jsonb not null default '[]'::jsonb,
    evidence    jsonb not null default '[]'::jsonb,   -- already redacted by the sensor
    status      text not null default 'open' check (status in ('open','acknowledged','closed')),
    note        text,
    updated_at  timestamptz not null default now(),
    unique (sensor_id, local_id)
);
create index if not exists incidents_sensor_idx on public.incidents(sensor_id, last_seen desc);

create table if not exists public.actions (
    id          bigserial primary key,
    sensor_id   uuid not null references public.sensors(id) on delete cascade,
    kind        text not null check (kind in ('rotate','alert_test','isolation_report')),
    args        jsonb not null default '{}'::jsonb,
    status      text not null default 'queued' check (status in ('queued','sent','done','failed')),
    result      jsonb,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);
create index if not exists actions_sensor_idx on public.actions(sensor_id, status);

create table if not exists public.audit_log (
    id          bigserial primary key,
    owner_id    uuid not null references auth.users(id) on delete cascade,
    sensor_id   uuid references public.sensors(id) on delete set null,
    command     text not null,
    created_at  timestamptz not null default now()
);
create index if not exists audit_owner_idx on public.audit_log(owner_id, created_at desc);

alter table public.sensors       enable row level security;
alter table public.sensor_config enable row level security;
alter table public.incidents     enable row level security;
alter table public.actions       enable row level security;
alter table public.audit_log     enable row level security;

revoke all on public.sensors, public.sensor_config, public.incidents, public.actions, public.audit_log
    from anon, authenticated;
