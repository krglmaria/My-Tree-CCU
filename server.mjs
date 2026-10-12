import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { ensureDatabase, pool } from './lib/database.mjs';

const scrypt = promisify(scryptCallback);
const projectDirectory = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT) || 3000;
const statuses = new Set(['planted', 'watered', 'established']);
const maxRequestBytes = 16 * 1024;
const maxActivityEntries = 100;
const sessionCookieName = 'mytree_session';
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const passwordParameters = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
}

function cookieValue(request, name) {
  const cookies = request.headers.cookie?.split(';') || [];
  const cookie = cookies.map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : null;
}

function setSessionCookie(request, response, token, maxAgeSeconds = sessionLifetimeMs / 1000) {
  const secure = request.socket?.encrypted || request.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  response.setHeader('Set-Cookie', `${sessionCookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure}`);
}

function clearSessionCookie(request, response) {
  setSessionCookie(request, response, '', 0);
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function validUsername(username) {
  return /^[a-z0-9._-]{3,32}$/.test(username);
}

function validPassword(password) {
  return typeof password === 'string' && password.length >= 10 && password.length <= 128;
}

async function hashPassword(password, salt = randomBytes(16)) {
  const derivedKey = await scrypt(password, salt, 64, passwordParameters);
  return {
    salt: Buffer.from(salt).toString('base64'),
    passwordHash: Buffer.from(derivedKey).toString('base64'),
    passwordParameters: { N: passwordParameters.N, r: passwordParameters.r, p: passwordParameters.p }
  };
}

async function verifyPassword(password, user) {
  const salt = user?.salt ? Buffer.from(user.salt, 'base64') : Buffer.alloc(16);
  const expected = user?.passwordHash ? Buffer.from(user.passwordHash, 'base64') : Buffer.alloc(64);
  const parameters = user?.passwordParameters || passwordParameters;
  const derivedKey = Buffer.from(await scrypt(password, salt, 64, { ...parameters, maxmem: 64 * 1024 * 1024 }));
  return timingSafeEqual(derivedKey, expected);
}

function mapTree(row) {
  return {
    id: row.id,
    name: row.name,
    plantedBy: row.planted_by,
    date: String(row.planted_on).slice(0, 10),
    status: row.status,
    careNotes: row.care_notes || '',
    nextWateringOn: row.next_watering_on ? String(row.next_watering_on).slice(0, 10) : ''
  };
}

function mapActivity(row) {
  return { id: row.id, treeName: row.tree_name, plantedBy: row.planted_by, action: row.action, timestamp: row.timestamp };
}

async function getCurrentUser(request) {
  const token = cookieValue(request, sessionCookieName);
  if (!token) return null;
  const tokenHash = Buffer.from(token, 'base64url').toString('hex');
  const result = await pool.query(`
    SELECT u.id, u.username, u.role
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = $1 AND s.expires_at > NOW()
  `, [tokenHash]);
  return result.rows[0] || null;
}

async function createSession(request, response, user) {
  const token = randomBytes(32).toString('base64url');
  const tokenHash = Buffer.from(token, 'base64url').toString('hex');
  await pool.query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
    tokenHash, user.id, new Date(Date.now() + sessionLifetimeMs)
  ]);
  setSessionCookie(request, response, token);
}

async function destroySession(request, response) {
  const token = cookieValue(request, sessionCookieName);
  if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [Buffer.from(token, 'base64url').toString('hex')]);
  clearSessionCookie(request, response);
}

function isSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

async function loginRateLimit(request) {
  const client = (request.headers['x-forwarded-for'] || request.socket?.remoteAddress || 'unknown').toString().split(',')[0].trim();
  await pool.query("DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '1 day'");
  const result = await pool.query(`
    SELECT COUNT(*)::int AS count FROM login_attempts
    WHERE client_key = $1 AND attempted_at > NOW() - INTERVAL '15 minutes'
  `, [client]);
  if (result.rows[0].count >= 10) return false;
  await pool.query('INSERT INTO login_attempts (client_key) VALUES ($1)', [client]);
  return true;
}

function requireRole(user, response, roles) {
  if (!user) {
    sendJson(response, 401, { error: 'Войдите в аккаунт, чтобы выполнить это действие.' });
    return false;
  }
  if (!roles.includes(user.role)) {
    sendJson(response, 403, { error: 'У вашей учётной записи нет прав на это действие.' });
    return false;
  }
  return true;
}

async function readJsonBody(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body) > maxRequestBytes) {
      const error = new Error('Размер запроса превышает допустимый.');
      error.statusCode = 413;
      throw error;
    }
  }
  try {
    return JSON.parse(body);
  } catch {
    const error = new Error('Некорректный JSON в запросе.');
    error.statusCode = 400;
    throw error;
  }
}

function isValidDate(date) {
  if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  const parsed = new Date(`${date}T00:00:00.000Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === date;
}

function makeActivity(tree, action) {
  return {
    id: randomUUID(),
    treeName: tree.name,
    plantedBy: tree.plantedBy,
    action,
    timestamp: new Date().toISOString()
  };
}

async function insertActivity(client, entry) {
  await client.query('INSERT INTO activity (id, tree_name, planted_by, action, timestamp) VALUES ($1, $2, $3, $4, $5)', [
    entry.id, entry.treeName, entry.plantedBy || '', entry.action, entry.timestamp
  ]);
  await client.query('DELETE FROM activity WHERE id IN (SELECT id FROM activity ORDER BY timestamp DESC OFFSET $1)', [maxActivityEntries]);
}

async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function handleApi(request, response, url) {
  await ensureDatabase();

  if (request.method === 'GET' && url.pathname === '/api/health') {
    await pool.query('SELECT 1');
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/auth/me') {
    const [userResult, user] = await Promise.all([
      pool.query('SELECT EXISTS (SELECT 1 FROM users) AS configured'),
      getCurrentUser(request)
    ]);
    sendJson(response, 200, { user: user ? publicUser(user) : null, setupRequired: !userResult.rows[0].configured });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/setup') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    const body = await readJsonBody(request);
    const username = normalizeUsername(body.username);
    if (!validUsername(username)) {
      sendJson(response, 400, { error: 'Логин: 3–32 символа, латинские буквы, цифры, точка, дефис или подчёркивание.' });
      return;
    }
    if (!validPassword(body.password)) {
      sendJson(response, 400, { error: 'Пароль должен содержать от 10 до 128 символов.' });
      return;
    }
    const passwordRecord = await hashPassword(body.password);
    const admin = await withTransaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(70417021)");
      const existing = await client.query('SELECT 1 FROM users LIMIT 1');
      if (existing.rowCount) return null;
      const user = { id: randomUUID(), username, role: 'admin', ...passwordRecord, createdAt: new Date().toISOString() };
      await client.query(`
        INSERT INTO users (id, username, role, salt, password_hash, password_parameters, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [user.id, user.username, user.role, user.salt, user.passwordHash, user.passwordParameters, user.createdAt]);
      return user;
    });
    if (!admin) {
      sendJson(response, 409, { error: 'Первичная настройка уже завершена. Войдите в аккаунт.' });
      return;
    }
    await createSession(request, response, admin);
    sendJson(response, 201, { user: publicUser(admin), setupRequired: false });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/login') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!await loginRateLimit(request)) {
      sendJson(response, 429, { error: 'Слишком много попыток. Повторите через 15 минут.' });
      return;
    }
    const body = await readJsonBody(request);
    const username = normalizeUsername(body.username);
    const password = typeof body.password === 'string' ? body.password.slice(0, 128) : '';
    const result = await pool.query(`
      SELECT id, username, role, salt, password_hash AS "passwordHash", password_parameters AS "passwordParameters"
      FROM users WHERE username = $1
    `, [username]);
    const user = result.rows[0];
    if (!await verifyPassword(password, user)) {
      sendJson(response, 401, { error: 'Неверный логин или пароль.' });
      return;
    }
    await createSession(request, response, user);
    sendJson(response, 200, { user: publicUser(user), setupRequired: false });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    await destroySession(request, response);
    sendJson(response, 200, { ok: true });
    return;
  }

  const currentUser = await getCurrentUser(request);

  if (request.method === 'GET' && url.pathname === '/api/users') {
    if (!requireRole(currentUser, response, ['admin'])) return;
    const result = await pool.query('SELECT id, username, role FROM users ORDER BY created_at');
    sendJson(response, 200, { users: result.rows });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/users') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin'])) return;
    const body = await readJsonBody(request);
    const username = normalizeUsername(body.username);
    if (!validUsername(username)) {
      sendJson(response, 400, { error: 'Логин: 3–32 символа, латинские буквы, цифры, точка, дефис или подчёркивание.' });
      return;
    }
    if (!validPassword(body.password)) {
      sendJson(response, 400, { error: 'Пароль должен содержать от 10 до 128 символов.' });
      return;
    }
    if (!['editor', 'viewer'].includes(body.role)) {
      sendJson(response, 400, { error: 'Выберите роль «редактор» или «только просмотр».' });
      return;
    }
    const passwordRecord = await hashPassword(body.password);
    const user = { id: randomUUID(), username, role: body.role, ...passwordRecord, createdAt: new Date().toISOString() };
    try {
      await pool.query(`
        INSERT INTO users (id, username, role, salt, password_hash, password_parameters, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [user.id, user.username, user.role, user.salt, user.passwordHash, user.passwordParameters, user.createdAt]);
    } catch (error) {
      if (error.code === '23505') {
        sendJson(response, 409, { error: 'Такой логин уже существует.' });
        return;
      }
      throw error;
    }
    sendJson(response, 201, { user: publicUser(user) });
    return;
  }

  const userRoute = url.pathname.match(/^\/api\/users\/([^/]+)$/);
  if (request.method === 'DELETE' && userRoute) {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin'])) return;
    const userId = decodeURIComponent(userRoute[1]);
    if (userId === currentUser.id) {
      sendJson(response, 400, { error: 'Нельзя удалить аккаунт, в который вы вошли.' });
      return;
    }
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
    if (!result.rowCount) {
      sendJson(response, 404, { error: 'Аккаунт не найден.' });
      return;
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/trees') {
    const [treeResult, activityResult] = await Promise.all([
      pool.query('SELECT * FROM trees ORDER BY planted_on DESC, id'),
      pool.query('SELECT * FROM activity ORDER BY timestamp DESC LIMIT $1', [maxActivityEntries])
    ]);
    sendJson(response, 200, { trees: treeResult.rows.map(mapTree), activity: activityResult.rows.map(mapActivity) });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/trees') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin', 'editor'])) return;
    const body = await readJsonBody(request);
    const tree = validateTree(body);
    if (tree.error) {
      sendJson(response, 400, { error: tree.error });
      return;
    }
    tree.id = randomUUID();
    const activity = makeActivity(tree, 'Добавлена посадка');
    await withTransaction(async (client) => {
      await saveTree(client, tree);
      await insertActivity(client, activity);
    });
    sendJson(response, 201, { tree, activity });
    return;
  }

  const statusRoute = url.pathname.match(/^\/api\/trees\/([^/]+)\/status$/);
  if (request.method === 'PATCH' && statusRoute) {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin', 'editor'])) return;
    const treeId = decodeURIComponent(statusRoute[1]);
    const body = await readJsonBody(request);
    if (!statuses.has(body.status)) {
      sendJson(response, 400, { error: 'Выберите один из доступных статусов дерева.' });
      return;
    }
    const existing = await pool.query('SELECT * FROM trees WHERE id = $1', [treeId]);
    if (!existing.rowCount) {
      sendJson(response, 404, { error: 'Дерево не найдено.' });
      return;
    }
    const tree = mapTree(existing.rows[0]);
    if (tree.status === body.status) {
      sendJson(response, 200, { tree, activity: null });
      return;
    }
    const previousStatus = tree.status;
    tree.status = body.status;
    const activity = makeActivity(tree, `Статус изменён: ${previousStatus} → ${body.status}`);
    await withTransaction(async (client) => {
      await client.query('UPDATE trees SET status = $2 WHERE id = $1', [tree.id, tree.status]);
      await insertActivity(client, activity);
    });
    sendJson(response, 200, { tree, activity });
    return;
  }

  const treeRoute = url.pathname.match(/^\/api\/trees\/([^/]+)$/);
  if (treeRoute && request.method === 'PATCH') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin', 'editor'])) return;
    const treeId = decodeURIComponent(treeRoute[1]);
    const body = await readJsonBody(request);
    const tree = validateTree(body);
    if (tree.error) {
      sendJson(response, 400, { error: tree.error });
      return;
    }
    const existing = await pool.query('SELECT id FROM trees WHERE id = $1', [treeId]);
    if (!existing.rowCount) {
      sendJson(response, 404, { error: 'Дерево не найдено.' });
      return;
    }
    tree.id = treeId;
    const activity = makeActivity(tree, 'Обновлена информация о посадке');
    await withTransaction(async (client) => {
      await saveTree(client, tree);
      await insertActivity(client, activity);
    });
    sendJson(response, 200, { tree, activity });
    return;
  }

  if (treeRoute && request.method === 'DELETE') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin', 'editor'])) return;
    const treeId = decodeURIComponent(treeRoute[1]);
    const result = await pool.query('SELECT * FROM trees WHERE id = $1', [treeId]);
    if (!result.rowCount) {
      sendJson(response, 404, { error: 'Дерево не найдено.' });
      return;
    }
    const tree = mapTree(result.rows[0]);
    const activity = makeActivity(tree, 'Удалена посадка');
    await withTransaction(async (client) => {
      await client.query('DELETE FROM trees WHERE id = $1', [treeId]);
      await insertActivity(client, activity);
    });
    sendJson(response, 200, { ok: true, activity });
    return;
  }

  sendJson(response, 404, { error: 'API-маршрут не найден.' });
}

function validateTree(body) {
  const tree = {
    name: typeof body.name === 'string' ? body.name.trim() : '',
    plantedBy: typeof body.plantedBy === 'string' ? body.plantedBy.trim() : '',
    date: typeof body.date === 'string' ? body.date : '',
    status: typeof body.status === 'string' ? body.status : '',
    careNotes: typeof body.careNotes === 'string' ? body.careNotes.trim() : '',
    nextWateringOn: typeof body.nextWateringOn === 'string' ? body.nextWateringOn : ''
  };
  if (!tree.name || tree.name.length > 48) return { error: 'Укажите имя дерева (не более 48 символов).' };
  if (!tree.plantedBy || tree.plantedBy.length > 32) return { error: 'Укажите студента или группу (не более 32 символов).' };
  if (!isValidDate(tree.date) || tree.date > new Date().toISOString().slice(0, 10)) return { error: 'Укажите корректную дату посадки не позднее сегодняшнего дня.' };
  if (!statuses.has(tree.status)) return { error: 'Выберите один из доступных статусов дерева.' };
  if (tree.careNotes.length > 1000) return { error: 'Заметка об уходе должна содержать не более 1000 символов.' };
  if (tree.nextWateringOn && !isValidDate(tree.nextWateringOn)) return { error: 'Укажите корректную дату следующего полива.' };
  return tree;
}

async function saveTree(client, tree) {
  await client.query(`
    INSERT INTO trees (id, name, planted_by, planted_on, status, care_notes, next_watering_on)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (id) DO UPDATE SET
      name = EXCLUDED.name, planted_by = EXCLUDED.planted_by, planted_on = EXCLUDED.planted_on,
      status = EXCLUDED.status, care_notes = EXCLUDED.care_notes, next_watering_on = EXCLUDED.next_watering_on
  `, [tree.id, tree.name, tree.plantedBy, tree.date, tree.status, tree.careNotes, tree.nextWateringOn || null]);
}

async function handleRequest(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) {
      await handleApi(request, response, url);
      return;
    }
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = readFileSync(join(projectDirectory, 'index.html'));
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      });
      response.end(html);
      return;
    }
    sendJson(response, 404, { error: 'Страница не найдена.' });
  } catch (error) {
    console.error(error);
    if (!response.headersSent) {
      sendJson(response, error.statusCode || (error.message === 'DATABASE_URL не настроен.' ? 503 : 500), {
        error: error.statusCode ? error.message : error.message === 'DATABASE_URL не настроен.'
          ? 'Сервер не настроен: укажите DATABASE_URL.'
          : 'Внутренняя ошибка сервера.'
      });
    } else {
      response.end();
    }
  }
}

export default handleRequest;

if (process.env.VERCEL !== '1') {
  createServer(handleRequest).listen(port, '127.0.0.1', () => {
    console.log(`My Tree CCU запущен: http://127.0.0.1:${port}`);
  });
}