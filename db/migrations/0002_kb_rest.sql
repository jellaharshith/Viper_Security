-- Server-side functions for the Supabase REST backend (src/viper/rag/reststore.py).
-- Apply after 0001_kb.sql. Callable only by the service role (the secret key); anon and
-- authenticated users get no table access and no function access.

create or replace function kb_search(p_collection text, p_embedding vector, p_k int)
returns table (id text, text text, source text, url text, title text, meta jsonb, score double precision)
language sql stable
set search_path = public, extensions
as $$
  select d.id, d.text, d.source, d.url, d.title, d.meta,
         1 - (d.embedding <=> p_embedding) as score
  from kb_docs d
  where d.collection = p_collection
  order by d.embedding <=> p_embedding
  limit least(greatest(p_k, 1), 100)
$$;

create or replace function kb_registry_change(p_event text, p_collection text default null)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  r kb_registry%rowtype;
  v_active text;
  v_prev text;
begin
  select * into r from kb_registry where singleton for update;  -- serialises concurrent changes
  if not found then
    raise exception 'kb: missing kb_registry row';
  end if;
  v_active := r.active;
  v_prev := r.previous;

  if p_event in ('bootstrap', 'promote')
     and (p_collection is null or p_collection !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$') then
    raise exception 'kb: invalid collection name';
  end if;

  if p_event = 'bootstrap' then
    if v_active is not null then
      return to_jsonb(r) - 'singleton';
    end if;
    v_active := p_collection;
  elsif p_event = 'promote' then
    if p_collection = v_active then
      raise exception 'kb: collection is already active';
    end if;
    v_prev := v_active;
    v_active := p_collection;
  elsif p_event = 'rollback' then
    if v_prev is null or v_prev = '' then
      raise exception 'kb: no previous collection to roll back to';
    end if;
    v_active := v_prev;
    v_prev := r.active;
  else
    raise exception 'kb: unknown event';
  end if;

  update kb_registry
     set active = v_active,
         previous = v_prev,
         history = history || jsonb_build_array(jsonb_build_object(
           'at', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"+00:00"'),
           'event', p_event,
           'collection', coalesce(v_active, '')))
   where singleton;

  select * into r from kb_registry where singleton;
  return to_jsonb(r) - 'singleton';
end
$$;

revoke all on table kb_docs, kb_registry from anon, authenticated;
revoke all on function kb_search(text, vector, int) from public, anon, authenticated;
revoke all on function kb_registry_change(text, text) from public, anon, authenticated;
grant execute on function kb_search(text, vector, int) to service_role;
grant execute on function kb_registry_change(text, text) to service_role;
