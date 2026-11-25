begin;

create schema gca_private;
revoke all on schema gca_private from public, anon, authenticated;
create extension if not exists pgcrypto with schema extensions;

create table gca_private.settings (
  singleton boolean primary key default true check (singleton),
  allowed_origins text[] not null default '{}'
);
insert into gca_private.settings default values;

create table gca_private.instructors (
  user_id uuid primary key references auth.users(id) on delete cascade
);
create table gca_private.classes (
  id uuid primary key default gen_random_uuid(),
  instructor_id uuid not null references gca_private.instructors on delete cascade,
  label text not null check (char_length(label) between 1 and 80),
  code_hash bytea not null unique,
  rounds_required smallint not null check (rounds_required between 1 and 20),
  is_open boolean not null default true
);
create index on gca_private.classes (instructor_id);
create table gca_private.participants (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references gca_private.classes on delete cascade,
  student_id uuid not null references auth.users(id) on delete cascade,
  student_name text not null,
  partner_name text not null default '',
  constraint gca_participant_identity unique (class_id, student_id, student_name, partner_name)
);
create table gca_private.sessions (
  id uuid primary key,
  participant_id uuid not null references gca_private.participants on delete cascade,
  activity_id text not null default 'ghost-coin',
  activity_version text not null default 'level2-pilot-1',
  schema_version smallint not null default 1,
  started_at timestamptz not null default now()
);
create index on gca_private.sessions (participant_id);
create table gca_private.events (
  event_id uuid primary key,
  session_id uuid not null references gca_private.sessions on delete cascade,
  seq integer not null,
  event_type text not null,
  round_id uuid,
  client_at timestamptz not null,
  elapsed_ms integer not null,
  received_at timestamptz not null default now(),
  payload jsonb not null,
  unique (session_id, seq)
);
create index on gca_private.events (session_id, round_id, event_type);
create unique index on gca_private.events (session_id, round_id, event_type)
  where event_type in ('round_start', 'round_resolved');
create table gca_private.resolved_rounds (
  session_id uuid not null references gca_private.sessions on delete cascade,
  round_id uuid not null,
  primary key (session_id, round_id)
);
create table gca_private.completions (
  participant_id uuid primary key references gca_private.participants on delete cascade,
  completed_at timestamptz not null default now(),
  rounds_required smallint not null
);
create table gca_private.request_limits (
  user_id uuid not null references auth.users on delete cascade,
  operation text not null,
  minute timestamptz not null,
  attempts integer not null,
  primary key (user_id, operation, minute)
);
create index on gca_private.request_limits (minute);

alter table gca_private.settings enable row level security;
alter table gca_private.instructors enable row level security;
alter table gca_private.classes enable row level security;
alter table gca_private.participants enable row level security;
alter table gca_private.sessions enable row level security;
alter table gca_private.events enable row level security;
alter table gca_private.resolved_rounds enable row level security;
alter table gca_private.completions enable row level security;
alter table gca_private.request_limits enable row level security;

create function gca_private.check_origin() returns void
language plpgsql set search_path = '' as $$
declare
  request_origin text := nullif(current_setting('request.headers', true), '')::jsonb ->> 'origin';
begin
  if request_origin is not null and not exists (
    select 1 from gca_private.settings where request_origin = any(allowed_origins)
  ) then
    raise exception 'This site is not authorized for this project' using errcode = '42501';
  end if;
end;
$$;

create function gca_private.require_instructor() returns uuid
language plpgsql set search_path = '' as $$
declare
  instructor uuid := auth.uid();
begin
  perform gca_private.check_origin();
  if coalesce(auth.jwt() ->> 'is_anonymous', 'true') <> 'false'
     or not exists (select 1 from gca_private.instructors where user_id = instructor) then
    raise exception 'Instructor access required' using errcode = '42501';
  end if;
  return instructor;
end;
$$;

create function gca_private.rate_limit(operation_name text, allowed integer) returns boolean
language plpgsql set search_path = '' as $$
declare
  current_minute timestamptz := date_trunc('minute', now());
  attempt_count integer;
begin
  delete from gca_private.request_limits where minute < current_minute - interval '1 day';
  insert into gca_private.request_limits as r (user_id, operation, minute, attempts)
    values (auth.uid(), operation_name, current_minute, 1)
    on conflict (user_id, operation, minute) do update set attempts = least(r.attempts + 1, allowed + 1)
    returning attempts into attempt_count;
  return attempt_count <= allowed;
end;
$$;

create function public.gca_enroll(p_class_code text, p_name text, p_partner text, p_session uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  student uuid := auth.uid();
  class_record gca_private.classes%rowtype;
  existing_participant gca_private.participants%rowtype;
  participant uuid;
  code text := upper(btrim(p_class_code));
  entered_name text := btrim(p_name);
  entered_partner text := coalesce(btrim(p_partner), '');
begin
  perform gca_private.check_origin();
  if student is null or coalesce(auth.jwt() ->> 'is_anonymous', 'false') <> 'true' then
    raise exception 'Student session required' using errcode = '42501';
  end if;
  if not gca_private.rate_limit('enrollment', 8) then
    return jsonb_build_object('error', 'Too many attempts. Try again in a minute.');
  end if;
  if p_session is null or code is null or code !~ '^[0-9A-F]{16}$'
     or entered_name is null or char_length(entered_name) not between 1 and 80
     or char_length(entered_partner) > 80 or entered_name ~ '[[:cntrl:]]' or entered_partner ~ '[[:cntrl:]]' then
    return jsonb_build_object('error', 'Enter a valid class code and name.');
  end if;

  select * into class_record from gca_private.classes
    where is_open and code_hash = extensions.digest(code, 'sha256');
  if not found then
    return jsonb_build_object('error', 'That class code is invalid or the class is closed.');
  end if;

  insert into gca_private.participants as p (class_id, student_id, student_name, partner_name)
    values (class_record.id, student, entered_name, entered_partner)
    on conflict on constraint gca_participant_identity
    do update set student_id = excluded.student_id
    returning p.id into participant;

  insert into gca_private.sessions (id, participant_id) values (p_session, participant)
    on conflict do nothing;
  if not exists (select 1 from gca_private.sessions where id = p_session and participant_id = participant) then
    raise exception 'Session is unavailable' using errcode = '42501';
  end if;

  return jsonb_build_object(
    'session_id', p_session,
    'rounds_required', class_record.rounds_required,
    'resolved_rounds', (
      select count(*) from gca_private.resolved_rounds r join gca_private.sessions s on s.id = r.session_id
      where s.participant_id = participant
    ),
    'completed_at', (select completed_at from gca_private.completions where participant_id = participant)
  );
end;
$$;

create function gca_private.valid_timing(t jsonb, elapsed integer) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(
    jsonb_typeof(t) = 'object'
    and t - array['visible_ms', 'active_ms', 'idle_ms', 'hidden_ms'] = '{}'::jsonb
    and (t -> 'visible_ms')::text ~ '^[0-9]{1,8}$'
    and (t -> 'active_ms')::text ~ '^[0-9]{1,8}$'
    and (t -> 'idle_ms')::text ~ '^[0-9]{1,8}$'
    and (t -> 'hidden_ms')::text ~ '^[0-9]{1,8}$'
    and (t ->> 'active_ms')::numeric + (t ->> 'idle_ms')::numeric = (t ->> 'visible_ms')::numeric
    and (t ->> 'visible_ms')::numeric + (t ->> 'hidden_ms')::numeric <= elapsed,
    false
  );
$$;

create function gca_private.valid_coin(s jsonb) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(
    jsonb_typeof(s) = 'object' and s - array['H', 'T'] = '{}'::jsonb
    and s -> 'H' in ('[]'::jsonb, '[1]'::jsonb, '[-1]'::jsonb)
    and s -> 'T' in ('[]'::jsonb, '[1]'::jsonb, '[-1]'::jsonb)
    and s <> '{"H":[],"T":[]}'::jsonb,
    false
  );
$$;

create function gca_private.valid_options(o jsonb) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(
    jsonb_typeof(o) = 'object' and o - array['computer_b', 'show_cards', 'resolve_together'] = '{}'::jsonb
    and jsonb_typeof(o -> 'computer_b') = 'boolean'
    and jsonb_typeof(o -> 'show_cards') = 'boolean'
    and jsonb_typeof(o -> 'resolve_together') = 'boolean',
    false
  );
$$;

create function gca_private.coin_after(s jsonb, card text) returns jsonb
language sql immutable set search_path = '' as $$
  select case
    when card = 'leave' then s
    when card = 'flip' then jsonb_build_object('H', s -> 'T', 'T', s -> 'H')
    when s -> 'T' = '[]'::jsonb then jsonb_build_object('H', s -> 'H', 'T', s -> 'H')
    when s -> 'H' = '[]'::jsonb then jsonb_build_object('H', s -> 'T', 'T', jsonb_build_array(-((s -> 'T' ->> 0)::integer)))
    when s -> 'H' = s -> 'T' then jsonb_build_object('H', s -> 'H', 'T', '[]'::jsonb)
    else jsonb_build_object('H', '[]'::jsonb, 'T', s -> 'H')
  end;
$$;

create function gca_private.valid_payload(kind text, data jsonb) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(case kind
    when 'round_start' then
      data -> 'initial' = '{"H":[1],"T":[]}'::jsonb
      and gca_private.valid_options(data - array['timing', 'initial'])
    when 'card_played' then
      data - array['timing','turn','player','actor','card','before','after'] = '{}'::jsonb
      and data -> 'turn' in ('1'::jsonb, '2'::jsonb, '3'::jsonb)
      and data ->> 'player' = case when data ->> 'turn' = '2' then 'B' else 'A' end
      and (data ->> 'card' in ('leave', 'flip') or (data ->> 'card' = 'ghost' and data ->> 'player' = 'A'))
      and (data ->> 'actor' = 'human' or (data ->> 'actor' = 'computer' and data ->> 'player' = 'B'))
      and gca_private.valid_coin(data -> 'before') and gca_private.valid_coin(data -> 'after')
      and data -> 'after' = gca_private.coin_after(data -> 'before', data ->> 'card')
    when 'round_resolved' then
      data - array['timing','cards','before_measurement','final_state','heads_probability','tails_probability',
        'outcome','winner','sampled','observed_all_cards','options'] = '{}'::jsonb
      and jsonb_typeof(data -> 'cards') = 'array' and data -> 'cards' -> 3 is null
      and data -> 'cards' ->> 0 in ('leave','flip','ghost')
      and data -> 'cards' ->> 1 in ('leave','flip')
      and data -> 'cards' ->> 2 in ('leave','flip','ghost')
      and gca_private.valid_coin(data -> 'before_measurement') and gca_private.valid_coin(data -> 'final_state')
      and data -> 'heads_probability' = case
        when data -> 'before_measurement' -> 'H' = '[]'::jsonb then '0'::jsonb
        when data -> 'before_measurement' -> 'T' = '[]'::jsonb then '1'::jsonb else '0.5'::jsonb end
      and data -> 'tails_probability' = case data -> 'heads_probability'
        when '0'::jsonb then '1'::jsonb when '1'::jsonb then '0'::jsonb else '0.5'::jsonb end
      and data ->> 'winner' = case data ->> 'outcome' when 'H' then 'A' when 'T' then 'B' end
      and data -> 'sampled' = to_jsonb(data -> 'heads_probability' = '0.5'::jsonb)
      and data -> 'final_state' = case data ->> 'outcome'
        when 'H' then jsonb_build_object('H', data -> 'before_measurement' -> 'H', 'T', '[]'::jsonb)
        when 'T' then jsonb_build_object('H', '[]'::jsonb, 'T', data -> 'before_measurement' -> 'T') end
      and (data ->> 'outcome' <> 'H' or data -> 'heads_probability' <> '0'::jsonb)
      and (data ->> 'outcome' <> 'T' or data -> 'heads_probability' <> '1'::jsonb)
      and jsonb_typeof(data -> 'observed_all_cards') = 'boolean'
      and gca_private.valid_options(data -> 'options')
    when 'round_restart' then
      data - array['timing','reason','abandoned'] = '{}'::jsonb
      and data ->> 'reason' in ('restart','level_select') and jsonb_typeof(data -> 'abandoned') = 'boolean'
    when 'option_changed' then
      data - array['timing','option','value'] = '{}'::jsonb
      and data ->> 'option' in ('computer_b','show_cards','resolve_together','solo_quick_play')
      and jsonb_typeof(data -> 'value') = 'boolean'
    when 'help_changed' then
      data - array['timing','section','open'] = '{}'::jsonb
      and data ->> 'section' in ('instructions','spoiler','teacher_notes') and jsonb_typeof(data -> 'open') = 'boolean'
    when 'completion_reached' then data - 'timing' = '{"confirmed":true}'::jsonb
    when 'visibility_changed' then data - array['timing','visible'] = '{}'::jsonb and jsonb_typeof(data -> 'visible') = 'boolean'
    when 'focus_changed' then data - array['timing','focused'] = '{}'::jsonb and jsonb_typeof(data -> 'focused') = 'boolean'
    when 'idle_changed' then data - array['timing','idle'] = '{}'::jsonb and jsonb_typeof(data -> 'idle') = 'boolean'
    when 'cards_revealed' then data - array['timing','automatic'] = '{}'::jsonb and jsonb_typeof(data -> 'automatic') = 'boolean'
    when 'coin_tossed' then data - array['timing','automatic'] = '{}'::jsonb and jsonb_typeof(data -> 'automatic') = 'boolean'
    when 'autoplay_changed' then data - array['timing','enabled'] = '{}'::jsonb and jsonb_typeof(data -> 'enabled') = 'boolean'
    when 'measurement_opened' then
      data - array['timing','heads_probability','automatic'] = '{}'::jsonb
      and data -> 'heads_probability' in ('0'::jsonb, '0.5'::jsonb, '1'::jsonb)
      and jsonb_typeof(data -> 'automatic') = 'boolean'
    when 'move_advanced' then
      data - array['timing','frame','settled'] = '{}'::jsonb
      and (data -> 'frame')::text ~ '^[0-9]{1,2}$' and jsonb_typeof(data -> 'settled') = 'boolean'
    else data - 'timing' = '{}'::jsonb
  end, false);
$$;

create function gca_private.count_round(p_session uuid, p_round uuid, p_seq integer, data jsonb)
returns boolean language plpgsql set search_path = '' as $$
declare
  cards jsonb;
  turns jsonb;
  before_cards jsonb[];
  after_cards jsonb[];
  start_seq integer;
begin
  select min(seq) into start_seq from gca_private.events
    where session_id = p_session and round_id = p_round and event_type = 'round_start' and seq < p_seq;
  if start_seq is null then return false; end if;
  select jsonb_agg(payload -> 'card' order by seq), jsonb_agg(payload -> 'turn' order by seq),
    array_agg(payload -> 'before' order by seq), array_agg(payload -> 'after' order by seq)
    into cards, turns, before_cards, after_cards
    from gca_private.events where session_id = p_session and round_id = p_round
      and event_type = 'card_played' and seq > start_seq and seq < p_seq;
  if turns is distinct from '[1, 2, 3]'::jsonb or cards is distinct from data -> 'cards'
    or before_cards[1] is distinct from '{"H":[1],"T":[]}'::jsonb
    or before_cards[2] is distinct from after_cards[1] or before_cards[3] is distinct from after_cards[2]
    or data -> 'before_measurement' is distinct from after_cards[3]
    or exists (
      select 1 from gca_private.events where session_id = p_session and round_id = p_round
        and event_type = 'round_restart' and seq > start_seq and seq < p_seq
    ) then
    return false;
  end if;
  insert into gca_private.resolved_rounds values (p_session, p_round) on conflict do nothing;
  return found;
end;
$$;

create function public.gca_ingest(p_session uuid, p_events jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  participant uuid;
  required_rounds smallint;
  entry jsonb;
  kind text;
  data jsonb;
  entry_id uuid;
  entry_seq integer;
  round_uuid uuid;
  event_time timestamptz;
  elapsed integer;
  existing gca_private.events%rowtype;
  acknowledged uuid[] := '{}';
  resolved_count integer;
begin
  perform gca_private.check_origin();
  if auth.uid() is null or coalesce(auth.jwt() ->> 'is_anonymous', 'false') <> 'true' then
    raise exception 'Student session required' using errcode = '42501';
  end if;
  if not gca_private.rate_limit('ingestion', 100) then
    return jsonb_build_object('error', 'Too many save requests. Trying again shortly.');
  end if;
  select p.id, c.rounds_required into participant, required_rounds
    from gca_private.sessions s
    join gca_private.participants p on p.id = s.participant_id
    join gca_private.classes c on c.id = p.class_id
    where s.id = p_session and p.student_id = auth.uid() and c.is_open
    for update of p;
  if not found then raise exception 'Session is unavailable' using errcode = '42501'; end if;
  if jsonb_typeof(p_events) is distinct from 'array' or octet_length(p_events::text) > 48000 then
    raise exception 'Invalid event batch' using errcode = '22023';
  end if;
  if jsonb_array_length(p_events) not between 1 and 30 then
    raise exception 'Invalid event batch' using errcode = '22023';
  end if;

  for entry in select value from jsonb_array_elements(p_events) order by (value ->> 'seq')::integer loop
    entry_id := (entry ->> 'event_id')::uuid;
    entry_seq := (entry ->> 'seq')::integer;
    elapsed := (entry ->> 'elapsed_ms')::integer;
    event_time := (entry ->> 'client_at')::timestamptz;
    round_uuid := (entry ->> 'round_id')::uuid;
    kind := entry ->> 'type';
    data := entry -> 'payload';
    if entry_id is null or entry_seq is null or entry_seq not between 1 and 20000
      or elapsed is null or elapsed not between 0 and 86400000
      or event_time is null or not isfinite(event_time)
      or entry ->> 'activity_id' is distinct from 'ghost-coin'
      or entry ->> 'activity_version' is distinct from 'level2-pilot-1'
      or entry ->> 'schema_version' is distinct from '1' or entry ->> 'level' is distinct from '2'
      or kind is null or kind not in (
        'level_enter', 'level_exit', 'round_start', 'card_played', 'option_changed',
        'round_resolved', 'round_restart', 'score_reset', 'help_changed', 'visibility_changed',
        'focus_changed', 'idle_changed', 'timing_snapshot', 'completion_reached',
        'session_pause', 'session_resume', 'cards_revealed', 'move_advanced',
        'measurement_opened', 'coin_tossed', 'autoplay_changed'
      )
      or jsonb_typeof(data) is distinct from 'object' or octet_length(data::text) > 1000
      or not gca_private.valid_timing(data -> 'timing', elapsed) or not gca_private.valid_payload(kind, data)
      or (kind in ('round_start', 'card_played', 'round_resolved', 'round_restart') and round_uuid is null) then
      raise exception 'Invalid event format' using errcode = '22023';
    end if;
    select * into existing from gca_private.events where event_id = entry_id;
    if found then
      if (existing.session_id, existing.seq, existing.event_type, existing.round_id, existing.client_at, existing.elapsed_ms, existing.payload)
          is distinct from (p_session, entry_seq, kind, round_uuid, event_time, elapsed, data) then
        raise exception 'Event identifier already used' using errcode = '22023';
      end if;
    else
      insert into gca_private.events (event_id, session_id, seq, event_type, round_id, client_at, elapsed_ms, payload)
        values (entry_id, p_session, entry_seq, kind, round_uuid, event_time, elapsed, data);
    end if;
    acknowledged := array_append(acknowledged, entry_id);
  end loop;

  -- An older batch can be retried after the resolution batch. Recheck only rounds touched here.
  for existing in
    select e.* from gca_private.events e where e.session_id = p_session and e.event_type = 'round_resolved'
      and exists (select 1 from jsonb_array_elements(p_events) v where (v ->> 'round_id')::uuid = e.round_id)
      and not exists (select 1 from gca_private.resolved_rounds r where r.session_id = e.session_id and r.round_id = e.round_id)
  loop
    perform gca_private.count_round(p_session, existing.round_id, existing.seq, existing.payload);
  end loop;

  select count(*) into resolved_count from gca_private.resolved_rounds r
    join gca_private.sessions s on s.id = r.session_id where s.participant_id = participant;
  if resolved_count >= required_rounds then
    insert into gca_private.completions (participant_id, rounds_required) values (participant, required_rounds)
      on conflict do nothing;
  end if;
  return jsonb_build_object(
    'acknowledged', to_jsonb(acknowledged), 'resolved_rounds', resolved_count, 'rounds_required', required_rounds,
    'completed_at', (select completed_at from gca_private.completions where participant_id = participant)
  );
end;
$$;

create function public.gca_classes() returns table (id uuid, label text, rounds_required smallint, is_open boolean)
language plpgsql security definer set search_path = '' as $$
declare owner_id uuid := gca_private.require_instructor();
begin
  return query select c.id, c.label, c.rounds_required, c.is_open from gca_private.classes c
    where c.instructor_id = owner_id order by c.label, c.id;
end;
$$;

create function public.gca_save_class(p_class uuid, p_label text, p_rounds integer, p_open boolean, p_rotate boolean)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  owner_id uuid := gca_private.require_instructor();
  new_code text;
  class_uuid uuid;
begin
  if p_label is null or char_length(btrim(p_label)) not between 1 and 80 or p_label ~ '[[:cntrl:]]'
    or p_rounds is null or p_rounds not between 1 and 20 or p_open is null or p_rotate is null then
    raise exception 'Invalid class settings' using errcode = '22023';
  end if;
  if p_class is null or p_rotate then
    new_code := upper(encode(extensions.gen_random_bytes(8), 'hex'));
  end if;
  if p_class is null then
    insert into gca_private.classes (instructor_id, label, rounds_required, is_open, code_hash)
      values (owner_id, btrim(p_label), p_rounds, p_open, extensions.digest(new_code, 'sha256'))
      returning id into class_uuid;
  else
    update gca_private.classes
      set label = btrim(p_label), rounds_required = p_rounds, is_open = p_open,
        code_hash = coalesce(extensions.digest(new_code, 'sha256'), code_hash)
      where id = p_class and instructor_id = owner_id returning id into class_uuid;
    if not found then raise exception 'Class is unavailable' using errcode = '42501'; end if;
  end if;
  return jsonb_build_object('class_id', class_uuid, 'class_code', new_code);
end;
$$;

create function public.gca_sessions(p_class uuid, p_offset integer default 0, p_limit integer default 100)
returns table (
  session_id uuid, participant_id uuid, student_name text, partner_name text, first_recorded timestamptz,
  last_recorded timestamptz, session_started timestamptz, completed_at timestamptz, completion_rounds smallint,
  timing jsonb, latest_event text, resolved_rounds bigint, abandoned_rounds bigint, restarts bigint,
  human_moves bigint, computer_moves bigint, sequences jsonb
)
language plpgsql security definer set search_path = '' as $$
declare owner_id uuid := gca_private.require_instructor();
begin
  if not exists (select 1 from gca_private.classes c where c.id = p_class and c.instructor_id = owner_id) then
    raise exception 'Class is unavailable' using errcode = '42501';
  end if;
  return query
    with page as (
      select s.id, s.started_at, p.id as person_id, p.student_name, p.partner_name
      from gca_private.sessions s join gca_private.participants p on p.id = s.participant_id
      where p.class_id = p_class order by s.started_at desc, s.id
      offset greatest(p_offset, 0) limit least(greatest(p_limit, 1), 100)
    )
    select page.id, page.person_id, page.student_name, page.partner_name, a.first_at, a.last_at,
      page.started_at, c.completed_at, c.rounds_required,
      last_event.payload -> 'timing', last_event.event_type,
      a.resolved, a.abandoned, a.restarted, a.human, a.computer,
      coalesce(seq_summary.sequences, '[]'::jsonb)
    from page left join gca_private.completions c on c.participant_id = page.person_id
    left join lateral (
      select payload, event_type from gca_private.events e where e.session_id = page.id order by seq desc limit 1
    ) last_event on true
    cross join lateral (
      select min(e.received_at) as first_at, max(e.received_at) as last_at,
        count(distinct round_id) filter (where event_type = 'round_resolved') as resolved,
        count(distinct round_id) filter (where event_type = 'round_restart' and payload ->> 'abandoned' = 'true') as abandoned,
        count(*) filter (where event_type = 'round_restart' and payload ->> 'reason' = 'restart') as restarted,
        count(*) filter (where event_type = 'card_played' and payload ->> 'actor' = 'human') as human,
        count(*) filter (where event_type = 'card_played' and payload ->> 'actor' = 'computer') as computer
      from gca_private.events e where e.session_id = page.id
    ) a
    left join lateral (
      select jsonb_agg(to_jsonb(q) order by q.cards) as sequences from (
        select payload -> 'cards' as cards,
          count(*) filter (where payload ->> 'outcome' = 'H') as heads,
          count(*) filter (where payload ->> 'outcome' = 'T') as tails
        from (
          select distinct on (round_id) round_id, payload from gca_private.events e
          where e.session_id = page.id and event_type = 'round_resolved' order by round_id, seq
        ) rounds group by payload -> 'cards'
      ) q
    ) seq_summary on true
    order by page.started_at desc, page.id;
end;
$$;

create function public.gca_events(p_session uuid, p_after integer default 0)
returns table (
  seq integer, event_id uuid, round_id uuid, event_type text, elapsed_ms integer, client_at timestamptz,
  received_at timestamptz, payload jsonb
)
language plpgsql security definer set search_path = '' as $$
declare owner_id uuid := gca_private.require_instructor();
begin
  if not exists (
    select 1 from gca_private.sessions s join gca_private.participants p on p.id = s.participant_id
      join gca_private.classes c on c.id = p.class_id where s.id = p_session and c.instructor_id = owner_id
  ) then raise exception 'Session is unavailable' using errcode = '42501'; end if;
  return query select e.seq, e.event_id, e.round_id, e.event_type, e.elapsed_ms, e.client_at, e.received_at, e.payload
    from gca_private.events e where e.session_id = p_session and e.seq > greatest(p_after, 0) order by e.seq limit 200;
end;
$$;

create function public.gca_delete_participant(p_participant uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare owner_id uuid := gca_private.require_instructor();
begin
  delete from gca_private.participants p using gca_private.classes c
    where p.id = p_participant and p.class_id = c.id and c.instructor_id = owner_id;
  if not found then raise exception 'Participant is unavailable' using errcode = '42501'; end if;
end;
$$;

revoke execute on all functions in schema gca_private from public, anon, authenticated;
revoke execute on function
  public.gca_enroll(text, text, text, uuid), public.gca_ingest(uuid, jsonb),
  public.gca_classes(), public.gca_save_class(uuid, text, integer, boolean, boolean),
  public.gca_sessions(uuid, integer, integer), public.gca_events(uuid, integer),
  public.gca_delete_participant(uuid)
from public, anon, authenticated;
grant execute on function
  public.gca_enroll(text, text, text, uuid), public.gca_ingest(uuid, jsonb),
  public.gca_classes(), public.gca_save_class(uuid, text, integer, boolean, boolean),
  public.gca_sessions(uuid, integer, integer), public.gca_events(uuid, integer),
  public.gca_delete_participant(uuid)
to authenticated;

commit;
