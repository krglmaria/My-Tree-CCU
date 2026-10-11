import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(scryptCallback);
const projectDirectory = dirname(fileURLToPath(import.meta.url));
const legacyDataFile = process.env.MYTREE_DATA_FILE
  ? resolve(process.env.MYTREE_DATA_FILE)
  : join(projectDirectory, 'data', 'store.json');
const databaseFile = process.env.MYTREE_DATABASE_FILE
  ? resolve(process.env.MYTREE_DATABASE_FILE)
  : join(projectDirectory, 'data', 'my-tree-ccu.sqlite');
const port = Number(process.env.PORT) || 3000;
const statuses = new Set(['planted', 'watered', 'established']);
const maxRequestBytes = 16 * 1024;
const maxActivityEntries = 100;
const sessionCookieName = 'mytree_session';
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const passwordParameters = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const sessions = new Map();
const loginAttempts = new Map();
let setupInProgress = false;

mkdirSync(dirname(databaseFile), { recursive: true });
const database = new DatabaseSync(databaseFile);
database.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS trees (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    planted_by TEXT NOT NULL,
    planted_on TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('planted', 'watered', 'established'))
  );
  CREATE TABLE IF NOT EXISTS activity (
    id TEXT PRIMARY KEY,
    tree_name TEXT NOT NULL,
    planted_by TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_parameters TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS activity_timestamp_idx ON activity(timestamp DESC);
`);

const demoStore = {
  trees: [
    { id: 'seed-1', name: 'Дуб «CCU-1»', plantedBy: 'Э-21', date: '2026-10-08', status: 'planted' },
    { id: 'seed-2', name: 'Берёза «Самал»', plantedBy: 'ИТ-22', date: '2026-10-02', status: 'watered' },
    { id: 'seed-3', name: 'Клён «Жасыл»', plantedBy: 'Д-21', date: '2026-09-25', status: 'established' },
    { id: 'seed-4', name: 'Яблоня «Үміт»', plantedBy: 'Э-23', date: '2026-09-18', status: 'established' }
  ],
  activity: []
};

function importLegacyData() {
  const migration = database.prepare('SELECT value FROM app_meta WHERE key = ?').get('json-import-v1');
  if (migration) return;

  let store = demoStore;
  if (existsSync(legacyDataFile)) {
    store = JSON.parse(readFileSync(legacyDataFile, 'utf8'));
  }

  store.trees ||= [];
  store.activity ||= [];
  store.users ||= [];

  const insertTree = database.prepare('INSERT OR IGNORE INTO trees (id, name, planted_by, planted_on, status) VALUES (?, ?, ?, ?, ?)');
  const insertActivity = database.prepare('INSERT OR IGNORE INTO activity (id, tree_name, planted_by, action, timestamp) VALUES (?, ?, ?, ?, ?)');
  const insertUser = database.prepare('INSERT OR IGNORE INTO users (id, username, role, salt, password_hash, password_parameters, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');

  database.exec('BEGIN IMMEDIATE');
  try {
    for (const tree of store.trees) {
      insertTree.run(tree.id, tree.name, tree.plantedBy || tree.group || '', tree.date, tree.status);
    }
    for (const entry of store.activity) {
      insertActivity.run(entry.id, entry.treeName, entry.plantedBy || '', entry.action, entry.timestamp);
    }
    for (const user of store.users) {
      insertUser.run(
        user.id,
        user.username,
        user.role,
        user.salt,
        user.passwordHash,
        JSON.stringify(user.passwordParameters || passwordParameters),
        user.createdAt || new Date().toISOString()
      );
    }
    database.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').run('json-import-v1', new Date().toISOString());
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function readStore() {
  importLegacyData();
  const trees = database.prepare('SELECT id, name, planted_by AS plantedBy, planted_on AS date, status FROM trees ORDER BY rowid').all();
  const activity = database.prepare('SELECT id, tree_name AS treeName, planted_by AS plantedBy, action, timestamp FROM activity ORDER BY timestamp DESC, rowid DESC').all();
  const users = database.prepare('SELECT id, username, role, salt, password_hash AS passwordHash, password_parameters AS passwordParameters, created_at AS createdAt FROM users ORDER BY rowid').all()
    .map((user) => ({ ...user, passwordParameters: JSON.parse(user.passwordParameters) }));
  return { trees, activity, users };
}

function writeStore(store) {
  database.exec('BEGIN IMMEDIATE');
  try {
    database.exec('DELETE FROM activity; DELETE FROM trees; DELETE FROM users;');
    const insertTree = database.prepare('INSERT INTO trees (id, name, planted_by, planted_on, status) VALUES (?, ?, ?, ?, ?)');
    const insertActivity = database.prepare('INSERT INTO activity (id, tree_name, planted_by, action, timestamp) VALUES (?, ?, ?, ?, ?)');
    const insertUser = database.prepare('INSERT INTO users (id, username, role, salt, password_hash, password_parameters, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');

    for (const tree of store.trees) insertTree.run(tree.id, tree.name, tree.plantedBy, tree.date, tree.status);
    for (const entry of store.activity) insertActivity.run(entry.id, entry.treeName, entry.plantedBy || '', entry.action, entry.timestamp);
    for (const user of store.users) {
      insertUser.run(user.id, user.username, user.role, user.salt, user.passwordHash, JSON.stringify(user.passwordParameters), user.createdAt);
    }

    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

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
  const secure = request.socket.encrypted ? '; Secure' : '';
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

function getCurrentUser(request, store) {
  const token = cookieValue(request, sessionCookieName);
  if (!token) return null;
  const tokenHash = Buffer.from(token, 'base64url').toString('hex');
  const session = sessions.get(tokenHash);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(tokenHash);
    return null;
  }
  return store.users.find((user) => user.id === session.userId) || null;
}

function createSession(request, response, user) {
  const token = randomBytes(32).toString('base64url');
  const tokenHash = Buffer.from(token, 'base64url').toString('hex');
  sessions.set(tokenHash, { userId: user.id, expiresAt: Date.now() + sessionLifetimeMs });
  setSessionCookie(request, response, token);
}

function destroySession(request, response) {
  const token = cookieValue(request, sessionCookieName);
  if (token) sessions.delete(Buffer.from(token, 'base64url').toString('hex'));
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

function loginRateLimit(request) {
  const client = request.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const attempts = (loginAttempts.get(client) || []).filter((time) => now - time < 15 * 60 * 1000);
  if (attempts.length >= 10) {
    loginAttempts.set(client, attempts);
    return false;
  }
  attempts.push(now);
  loginAttempts.set(client, attempts);
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
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
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

async function handleApi(request, response, url) {
  if (request.method === 'GET' && url.pathname === '/api/health') {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/auth/me') {
    const store = readStore();
    const user = getCurrentUser(request, store);
    sendJson(response, 200, { user: user ? publicUser(user) : null, setupRequired: store.users.length === 0 });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/setup') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    const store = readStore();
    if (store.users.length > 0 || setupInProgress) {
      sendJson(response, 409, { error: 'Первичная настройка уже завершена. Войдите в аккаунт.' });
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

    setupInProgress = true;
    try {
      const passwordRecord = await hashPassword(body.password);
      const latestStore = readStore();
      if (latestStore.users.length > 0) {
        sendJson(response, 409, { error: 'Первичная настройка уже завершена. Войдите в аккаунт.' });
        return;
      }
      const admin = { id: randomUUID(), username, role: 'admin', ...passwordRecord, createdAt: new Date().toISOString() };
      latestStore.users.push(admin);
      writeStore(latestStore);
      createSession(request, response, admin);
      sendJson(response, 201, { user: publicUser(admin), setupRequired: false });
    } finally {
      setupInProgress = false;
    }
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/login') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!loginRateLimit(request)) {
      sendJson(response, 429, { error: 'Слишком много попыток. Повторите через 15 минут.' });
      return;
    }

    const body = await readJsonBody(request);
    const username = normalizeUsername(body.username);
    const password = typeof body.password === 'string' ? body.password.slice(0, 128) : '';
    const store = readStore();
    const user = store.users.find((candidate) => candidate.username === username);
    const passwordMatches = await verifyPassword(password, user);
    if (!user || !passwordMatches) {
      sendJson(response, 401, { error: 'Неверный логин или пароль.' });
      return;
    }

    createSession(request, response, user);
    sendJson(response, 200, { user: publicUser(user), setupRequired: false });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    destroySession(request, response);
    sendJson(response, 200, { ok: true });
    return;
  }

  const store = readStore();
  const currentUser = getCurrentUser(request, store);

  if (request.method === 'GET' && url.pathname === '/api/users') {
    if (!requireRole(currentUser, response, ['admin'])) return;
    sendJson(response, 200, { users: store.users.map(publicUser) });
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
    const role = body.role;
    if (!validUsername(username)) {
      sendJson(response, 400, { error: 'Логин: 3–32 символа, латинские буквы, цифры, точка, дефис или подчёркивание.' });
      return;
    }
    if (!validPassword(body.password)) {
      sendJson(response, 400, { error: 'Пароль должен содержать от 10 до 128 символов.' });
      return;
    }
    if (!['editor', 'viewer'].includes(role)) {
      sendJson(response, 400, { error: 'Выберите роль «редактор» или «только просмотр».' });
      return;
    }
    if (store.users.some((user) => user.username === username)) {
      sendJson(response, 409, { error: 'Такой логин уже существует.' });
      return;
    }

    const passwordRecord = await hashPassword(body.password);
    const user = { id: randomUUID(), username, role, ...passwordRecord, createdAt: new Date().toISOString() };
    store.users.push(user);
    writeStore(store);
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
    const userIndex = store.users.findIndex((user) => user.id === userId);
    if (userIndex === -1) {
      sendJson(response, 404, { error: 'Аккаунт не найден.' });
      return;
    }

    store.users.splice(userIndex, 1);
    writeStore(store);
    for (const [tokenHash, session] of sessions) {
      if (session.userId === userId) sessions.delete(tokenHash);
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/trees') {
    sendJson(response, 200, { trees: store.trees, activity: store.activity });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/trees') {
    if (!isSameOrigin(request)) {
      sendJson(response, 403, { error: 'Недопустимый источник запроса.' });
      return;
    }
    if (!requireRole(currentUser, response, ['admin', 'editor'])) return;
    const body = await readJsonBody(request);
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const plantedBy = typeof body.plantedBy === 'string' ? body.plantedBy.trim() : '';
    const date = typeof body.date === 'string' ? body.date : '';
    const status = typeof body.status === 'string' ? body.status : '';

    if (!name || name.length > 48) {
      sendJson(response, 400, { error: 'Укажите имя дерева (не более 48 символов).' });
      return;
    }
    if (!plantedBy || plantedBy.length > 32) {
      sendJson(response, 400, { error: 'Укажите студента или группу (не более 32 символов).' });
      return;
    }
    if (!isValidDate(date) || date > new Date().toISOString().slice(0, 10)) {
      sendJson(response, 400, { error: 'Укажите корректную дату посадки не позднее сегодняшнего дня.' });
      return;
    }
    if (!statuses.has(status)) {
      sendJson(response, 400, { error: 'Выберите один из доступных статусов дерева.' });
      return;
    }

    const tree = { id: randomUUID(), name, plantedBy, date, status };
    const activity = makeActivity(tree, 'Добавлена посадка');
    store.trees.unshift(tree);
    store.activity.unshift(activity);
    store.activity = store.activity.slice(0, maxActivityEntries);
    writeStore(store);
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

    const tree = store.trees.find((item) => item.id === treeId);
    if (!tree) {
      sendJson(response, 404, { error: 'Дерево не найдено.' });
      return;
    }

    if (tree.status === body.status) {
      sendJson(response, 200, { tree, activity: null });
      return;
    }

    const previousStatus = tree.status;
    tree.status = body.status;
    const activity = makeActivity(tree, `Статус изменён: ${previousStatus} → ${body.status}`);
    store.activity.unshift(activity);
    store.activity = store.activity.slice(0, maxActivityEntries);
    writeStore(store);
    sendJson(response, 200, { tree, activity });
    return;
  }

  sendJson(response, 404, { error: 'API-маршрут не найден.' });
}

const server = createServer(async (request, response) => {
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
      sendJson(response, error.statusCode || 500, { error: error.statusCode ? error.message : 'Внутренняя ошибка сервера.' });
    } else {
      response.end();
    }
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`My Tree CCU запущен: http://127.0.0.1:${port}`);
});