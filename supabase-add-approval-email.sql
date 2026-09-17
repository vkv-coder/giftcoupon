-- store.html promises "you'll get an email once it's live" after registration,
-- but gc_admin_approve_store never sent anything - no email mechanism existed
-- anywhere in this app. Reuses the same shared relay worker pattern already
-- proven in sportbook's register_player_and_send_otp (see
-- https://telegram-notify.unigoods2026.workers.dev/, {action:'sendEmail',...}).

create or replace function public.gc_admin_approve_store(p_token uuid, p_store_id uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_email text;
  v_name text;
begin
  if not gc_admin_check_token(p_token) then
    raise exception 'Unauthorized';
  end if;

  update gc_stores set approved = true, approved_at = now() where store_id = p_store_id;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'Store not found');
  end if;

  select u.email::text, s.store_name into v_email, v_name
  from gc_stores s
  join auth.users u on u.id = s.owner_user_id
  where s.store_id = p_store_id;

  if v_email is not null then
    perform net.http_post(
      url := 'https://telegram-notify.unigoods2026.workers.dev/',
      headers := '{"Content-Type":"application/json"}'::jsonb,
      body := jsonb_build_object(
        'action','sendEmail','to',v_email,'subject','Your store is now live on Gift Coupon',
        'html','<p>Good news - <b>'||coalesce(v_name,'your store')||'</b> has been approved and is now live on Gift Coupon.</p><p>You can log in and start managing your coupons.</p>'
      )
    );
  end if;

  return jsonb_build_object('ok', true);
end;
$function$;
