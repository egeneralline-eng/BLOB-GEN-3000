// Cloudflare Pages Function: /api/likes
// GET  -> { count, liked }
// POST -> ставит лайк (один на устройство) и возвращает { count, liked }
//
// Нужно: D1-база с привязкой DB (см. schema.sql).
// Необязательно: секреты TURNSTILE_SECRET (капча) и IP_SALT (соль для хеша IP).

const MAX_PER_IP_PER_DAY = 3;   // сколько лайков в сутки разрешено с одного IP
const COOKIE = 'bg_dev';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });

function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function countLikes(db) {
  const row = await db.prepare('SELECT COUNT(*) AS n FROM likes').first();
  return row ? row.n : 0;
}

export async function onRequestGet({ request, env }) {
  if (!env.DB) return json({ error: 'no_db' }, 503);
  const dev = getCookie(request, COOKIE);
  let liked = false;
  if (dev && UUID_RE.test(dev)) {
    liked = !!(await env.DB.prepare('SELECT 1 FROM likes WHERE device = ?').bind(dev).first());
  }
  return json({ count: await countLikes(env.DB), liked });
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'no_db' }, 503);

  // Запросы только с этого же сайта
  const origin = request.headers.get('Origin');
  if (origin && new URL(origin).host !== new URL(request.url).host) {
    return json({ error: 'forbidden' }, 403);
  }

  let body = {};
  try { body = await request.json(); } catch (e) {}

  // 1. Этот девайс уже лайкал?
  let dev = getCookie(request, COOKIE);
  const hasDev = !!(dev && UUID_RE.test(dev));
  if (hasDev) {
    const done = await env.DB.prepare('SELECT 1 FROM likes WHERE device = ?').bind(dev).first();
    if (done) return json({ count: await countLikes(env.DB), liked: true, already: true });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // 2. Капча Turnstile (если секрет задан)
  if (env.TURNSTILE_SECRET) {
    const form = new FormData();
    form.append('secret', env.TURNSTILE_SECRET);
    form.append('response', body.token || '');
    if (ip !== 'unknown') form.append('remoteip', ip);
    const v = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form })
      .then(r => r.json()).catch(() => ({ success: false }));
    if (!v.success) return json({ error: 'captcha' }, 403);
  }

  // 3. Лимит по IP (храним только хеш, старые дни чистим)
  const h = await sha256(ip + '|' + (env.IP_SALT || 'blobgen'));
  const day = new Date().toISOString().slice(0, 10);
  await env.DB.prepare('DELETE FROM ip_hits WHERE day < ?').bind(day).run();
  const row = await env.DB.prepare(
    'INSERT INTO ip_hits (h, day, n) VALUES (?, ?, 1) ON CONFLICT (h, day) DO UPDATE SET n = n + 1 RETURNING n'
  ).bind(h, day).first();
  if (row && row.n > MAX_PER_IP_PER_DAY) {
    return json({ error: 'rate', count: await countLikes(env.DB) }, 429);
  }

  // 4. Записываем лайк
  if (!hasDev) dev = crypto.randomUUID();
  await env.DB.prepare('INSERT OR IGNORE INTO likes (device, created) VALUES (?, ?)').bind(dev, Date.now()).run();

  return json(
    { count: await countLikes(env.DB), liked: true },
    200,
    { 'Set-Cookie': `${COOKIE}=${dev}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax` }
  );
}
