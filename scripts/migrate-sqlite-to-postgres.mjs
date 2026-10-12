import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

process.env.VERCEL ||= '1';
const { ensureDatabase, pool } = await import('../server.mjs');
const sourceFile = resolve(process.env.MYTREE_DATABASE_FILE || 'data/my-tree-ccu.sqlite');

function asUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value || '')
    ? value
    : randomUUID();
}

if (!existsSync(sourceFile)) {
  throw new Error(`SQLite-файл не найден: ${sourceFile}`);
}

await ensureDatabase();
const source = new DatabaseSync(sourceFile, { readOnly: true });
const client = await pool.connect();

try {
  const trees = source.prepare('SELECT id, name, planted_by, planted_on, status FROM trees ORDER BY rowid').all();
  const activity = source.prepare('SELECT id, tree_name, planted_by, action, timestamp FROM activity ORDER BY rowid').all();
  const users = source.prepare('SELECT id, username, role, salt, password_hash, password_parameters, created_at FROM users ORDER BY rowid').all();

  await client.query('BEGIN');
  const counts = await client.query(`
    SELECT (SELECT COUNT(*) FROM trees) AS trees,
           (SELECT COUNT(*) FROM activity) AS activity,
           (SELECT COUNT(*) FROM users) AS users
  `);
  if (Object.values(counts.rows[0]).some((count) => Number(count) > 0)) {
    throw new Error('Целевая PostgreSQL-база не пуста. Миграция остановлена без изменений.');
  }

  for (const tree of trees) {
    await client.query('INSERT INTO trees (id, name, planted_by, planted_on, status) VALUES ($1, $2, $3, $4, $5)', [
      asUuid(tree.id), tree.name, tree.planted_by, tree.planted_on, tree.status
    ]);
  }
  for (const entry of activity) {
    await client.query('INSERT INTO activity (id, tree_name, planted_by, action, timestamp) VALUES ($1, $2, $3, $4, $5)', [
      asUuid(entry.id), entry.tree_name, entry.planted_by || '', entry.action, entry.timestamp
    ]);
  }
  for (const user of users) {
    await client.query(`
      INSERT INTO users (id, username, role, salt, password_hash, password_parameters, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [asUuid(user.id), user.username, user.role, user.salt, user.password_hash, JSON.parse(user.password_parameters), user.created_at]);
  }

  await client.query('COMMIT');
  console.log(`Перенесено: ${trees.length} посадок, ${activity.length} событий, ${users.length} аккаунтов.`);
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
  source.close();
  await pool.end();
}