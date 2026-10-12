const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const ENV_FILE = path.join(ROOT, '.env');
const PORT = Number(process.env.PORT) || 3000;
const SKILLS = new Set(['deploy', 'api', 'ai', 'chatbot', 'grade']);
const SESSION_COOKIE = 'talent_forge_session';
const SESSION_SECONDS = 7 * 24 * 60 * 60;

// Read simple KEY=value entries from .env without adding a runtime dependency.
try {
  const envText = fs.readFileSync(ENV_FILE, 'utf8');
  for (const line of envText.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
  }
} catch (error) { if (error.code !== 'ENOENT') throw error; }

let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  console.warn('SESSION_SECRET is not configured; sessions will reset when this instance restarts.');
}

function supabaseConfig() {
  const url = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url && !key) return null;
  if (!url || !key) { console.warn('Supabase is partially configured; using local JSON storage.'); return null; }
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith('.supabase.co')) throw new Error('SUPABASE_URL must be the HTTPS URL of your Supabase project.');
  return { url, key };
}
const cloudDb = supabaseConfig();

async function supabaseRequest(table, query, options = {}) {
  const response = await fetch(`${cloudDb.url}/rest/v1/${table}${query}`, {
    method: options.method || 'GET',
    headers: { apikey: cloudDb.key, 'Content-Type': 'application/json', ...(options.prefer ? { Prefer: options.prefer } : {}) },
    ...(options.body ? { body: JSON.stringify(options.body) } : {}),
  });
  let data = null;
  try { data = await response.json(); } catch {}
  if (!response.ok) {
    const error = new Error(data?.message || data?.hint || 'Database request failed.');
    error.status = response.status; error.code = data?.code; throw error;
  }
  return data;
}

function readDb() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; return { students: {}, results: [] }; }
}
function writeDb(db) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const temp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(db, null, 2));
  fs.renameSync(temp, DATA_FILE);
}
function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { body += chunk; if (body.length > 32_000) { reject(Object.assign(new Error('Request body too large'), { status: 413 })); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(Object.assign(new Error('Invalid JSON body'), { status: 400 })); } });
    req.on('error', reject);
  });
}
function validString(value, max) { return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max; }
function studentView(student) {
  return { usn: student.usn, name: student.name, department: student.department, semester: Number(student.semester), section: student.section };
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash: `scrypt$${salt}$${hash}` };
}
function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const [scheme, salt, expectedHex] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !/^[a-f0-9]{128}$/i.test(expectedHex || '')) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(actual, Buffer.from(expectedHex, 'hex'));
}
function createSession(usn) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const payload = Buffer.from(JSON.stringify({ usn, exp: expires })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}
function sessionUSN(req) {
  const cookie = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return null;
  const token = cookie.slice(SESSION_COOKIE.length + 1);
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return decoded.exp > Math.floor(Date.now() / 1000) && /^[A-Z0-9]{6,15}$/.test(decoded.usn) ? decoded.usn : null;
  } catch { return null; }
}
const sessionCookie = (token) => `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}`;
const clearCookie = `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;

async function findStudent(usn) {
  if (cloudDb) return (await supabaseRequest('students', `?usn=eq.${encodeURIComponent(usn)}&select=usn,name,department,semester,section,password_hash&limit=1`))[0] || null;
  return readDb().students[usn] || null;
}
async function saveStudent(student) {
  if (cloudDb) {
    await supabaseRequest('students', '', { method: 'POST', prefer: 'return=minimal', body: {
      usn: student.usn, name: student.name, department: student.department, semester: student.semester,
      section: student.section, password_hash: student.passwordHash,
    } });
    return;
  }
  const db = readDb(); db.students[student.usn] = student; writeDb(db);
}
async function upgradeLegacyStudent(student) {
  if (cloudDb) {
    await supabaseRequest('students', `?usn=eq.${encodeURIComponent(student.usn)}`, {
      method: 'PATCH', prefer: 'return=minimal', body: { password_hash: student.passwordHash },
    });
    return;
  }
  const db = readDb();
  db.students[student.usn].passwordHash = student.passwordHash;
  writeDb(db);
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  try {
    if (req.method === 'GET' && pathname === '/api/health') {
      if (cloudDb) {
        await supabaseRequest('students', '?select=usn,password_hash&limit=0');
        return sendJson(res, 200, { status: 'ok', database: 'supabase' });
      }
      return sendJson(res, 200, { status: 'ok', database: 'local-json' });
    }

    if (req.method === 'POST' && pathname === '/api/signup') {
      const body = await readBody(req);
      const student = {
        name: validString(body.name, 100) ? body.name.trim() : '',
        usn: typeof body.usn === 'string' ? body.usn.trim().toUpperCase() : '',
        department: validString(body.department, 80) ? body.department.trim() : '',
        semester: Number(body.semester),
        section: typeof body.section === 'string' ? body.section.trim().toUpperCase() : '',
        password: typeof body.password === 'string' ? body.password : '',
      };
      if (!student.name || !/^[A-Z0-9]{6,15}$/.test(student.usn) || !student.department ||
          !Number.isInteger(student.semester) || student.semester < 1 || student.semester > 8 ||
          !/^[A-Z0-9]{1,2}$/.test(student.section) || student.password.length < 8 || student.password.length > 200) {
        return sendJson(res, 400, { error: 'Check your details and use a password with at least 8 characters.' });
      }
      const passwordHash = hashPassword(student.password).hash;
      const record = { ...student, passwordHash, createdAt: new Date().toISOString() };
      delete record.password;
      const existing = await findStudent(student.usn);
      if (existing) {
        const sameStudent = existing.name?.trim().toLowerCase() === student.name.toLowerCase() &&
          existing.department?.trim().toLowerCase() === student.department.toLowerCase() &&
          Number(existing.semester) === student.semester && existing.section?.trim().toUpperCase() === student.section;
        if (existing.password_hash || existing.passwordHash || !sameStudent) {
          return sendJson(res, 409, { error: 'An account with this USN already exists. Please log in.' });
        }
        await upgradeLegacyStudent({ ...existing, usn: student.usn, passwordHash });
        return sendJson(res, 200, { student: studentView(existing) }, { 'Set-Cookie': sessionCookie(createSession(student.usn)) });
      }
      try { await saveStudent(record); }
      catch (error) { if (error.code === '23505' || error.status === 409) return sendJson(res, 409, { error: 'An account with this USN already exists. Please log in.' }); throw error; }
      return sendJson(res, 201, { student: studentView(record) }, { 'Set-Cookie': sessionCookie(createSession(student.usn)) });
    }

    if (req.method === 'POST' && pathname === '/api/login') {
      const body = await readBody(req);
      const usn = typeof body.usn === 'string' ? body.usn.trim().toUpperCase() : '';
      const password = typeof body.password === 'string' ? body.password : '';
      if (!/^[A-Z0-9]{6,15}$/.test(usn) || !password) return sendJson(res, 400, { error: 'Enter your USN and password.' });
      const student = await findStudent(usn);
      if (!student || !verifyPassword(password, student.password_hash || student.passwordHash)) return sendJson(res, 401, { error: 'The USN or password is incorrect.' });
      return sendJson(res, 200, { student: studentView(student) }, { 'Set-Cookie': sessionCookie(createSession(usn)) });
    }

    if (req.method === 'GET' && pathname === '/api/me') {
      const usn = sessionUSN(req);
      if (!usn) return sendJson(res, 401, { error: 'Please log in.' });
      const student = await findStudent(usn);
      if (!student) return sendJson(res, 401, { error: 'Please log in.' }, { 'Set-Cookie': clearCookie });
      return sendJson(res, 200, { student: studentView(student) });
    }

    if (req.method === 'POST' && pathname === '/api/logout') return sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearCookie });

    if (req.method === 'POST' && pathname === '/api/results') {
      const usn = sessionUSN(req);
      if (!usn) return sendJson(res, 401, { error: 'Your session expired. Please log in again.' }, { 'Set-Cookie': clearCookie });
      const body = await readBody(req);
      const skill = typeof body.skill === 'string' ? body.skill : '';
      const score = Number(body.score);
      const durationSeconds = Number(body.durationSeconds);
      if (!SKILLS.has(skill) || !Number.isInteger(score) || score < 0 || score > 100 ||
          !Number.isInteger(durationSeconds) || durationSeconds < 0 || durationSeconds > 900 ||
          !Array.isArray(body.checks) || body.checks.length > 20 || body.checks.some((value) => typeof value !== 'boolean') ||
          (body.answer !== undefined && (typeof body.answer !== 'string' || body.answer.length > 2000))) {
        return sendJson(res, 400, { error: 'The challenge result is invalid.' });
      }
      const result = { usn, skill, score, durationSeconds, checks: body.checks, answer: typeof body.answer === 'string' ? body.answer.trim() : '' };
      if (cloudDb) await supabaseRequest('challenge_results', '', { method: 'POST', prefer: 'return=minimal', body: {
        usn, skill, score, duration_seconds: durationSeconds, checks: body.checks, answer: result.answer,
      } });
      else { const db = readDb(); if (!db.students[usn]) return sendJson(res, 401, { error: 'Please log in again.' }); db.results.push({ id: `${Date.now()}-${crypto.randomBytes(3).toString('hex')}`, ...result, createdAt: new Date().toISOString() }); writeDb(db); }
      return sendJson(res, 201, { result: { skill, score, durationSeconds } });
    }

    if (req.method.startsWith('GET')) {
      const files = { '/': 'index.html', '/index.html': 'index.html', '/style.css': 'style.css' };
      const file = files[pathname];
      if (file) {
        const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8' };
        res.writeHead(200, { 'Content-Type': types[path.extname(file)] });
        return fs.createReadStream(path.join(ROOT, file)).pipe(res);
      }
    }
    return sendJson(res, 404, { error: 'Not found.' });
  } catch (error) {
    if (error.name === 'TypeError' && String(error.message).includes('fetch')) return sendJson(res, 503, { error: 'Cannot reach Supabase. Check the project URL and network connection.' });
    if (cloudDb && (error.code === 'PGRST204' || error.code === '42703' || /password_hash.*(column|schema cache)|(column|schema cache).*password_hash/i.test(error.message))) {
      return sendJson(res, 503, { error: 'Supabase needs the student password column. In its SQL Editor, run: alter table public.students add column if not exists password_hash text;' });
    }
    if (cloudDb && error.status >= 400 && error.status < 500) {
      console.error('Supabase request rejected:', error.message);
      return sendJson(res, 503, { error: 'Supabase rejected the request. Apply the latest schema.sql in the Supabase SQL Editor.' });
    }
    return sendJson(res, error.status || 500, { error: error.status ? error.message : 'The server could not complete the request.' });
  }
});

server.listen(PORT, () => console.log(`Talent Forge is running at http://localhost:${PORT}`));
