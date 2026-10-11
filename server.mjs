import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDirectory = dirname(fileURLToPath(import.meta.url));
const dataFile = process.env.MYTREE_DATA_FILE
  ? resolve(process.env.MYTREE_DATA_FILE)
  : join(projectDirectory, 'data', 'store.json');
const port = Number(process.env.PORT) || 3000;
const statuses = new Set(['planted', 'watered', 'established']);
const maxRequestBytes = 16 * 1024;
const maxActivityEntries = 100;

const demoStore = {
  trees: [
    { id: 'seed-1', name: 'Дуб «CCU-1»', plantedBy: 'Э-21', date: '2026-10-08', status: 'planted' },
    { id: 'seed-2', name: 'Берёза «Самал»', plantedBy: 'ИТ-22', date: '2026-10-02', status: 'watered' },
    { id: 'seed-3', name: 'Клён «Жасыл»', plantedBy: 'Д-21', date: '2026-09-25', status: 'established' },
    { id: 'seed-4', name: 'Яблоня «Үміт»', plantedBy: 'Э-23', date: '2026-09-18', status: 'established' }
  ],
  activity: []
};

function ensureStore() {
  if (existsSync(dataFile)) return;
  mkdirSync(dirname(dataFile), { recursive: true });
  writeFileSync(dataFile, JSON.stringify(demoStore, null, 2), 'utf8');
}

function readStore() {
  ensureStore();
  return JSON.parse(readFileSync(dataFile, 'utf8'));
}

function writeStore(store) {
  writeFileSync(dataFile, JSON.stringify(store, null, 2), 'utf8');
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
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

  if (request.method === 'GET' && url.pathname === '/api/trees') {
    sendJson(response, 200, readStore());
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/trees') {
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
    const store = readStore();
    store.trees.unshift(tree);
    store.activity.unshift(activity);
    store.activity = store.activity.slice(0, maxActivityEntries);
    writeStore(store);
    sendJson(response, 201, { tree, activity });
    return;
  }

  const statusRoute = url.pathname.match(/^\/api\/trees\/([^/]+)\/status$/);
  if (request.method === 'PATCH' && statusRoute) {
    const treeId = decodeURIComponent(statusRoute[1]);
    const body = await readJsonBody(request);
    if (!statuses.has(body.status)) {
      sendJson(response, 400, { error: 'Выберите один из доступных статусов дерева.' });
      return;
    }

    const store = readStore();
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