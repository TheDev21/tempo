const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Database setup — use RAILWAY_VOLUME_MOUNT_PATH if available (persistent volume)
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? process.env.RAILWAY_VOLUME_MOUNT_PATH
  : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'tempo.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS businesses (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_id TEXT NOT NULL,
    name TEXT NOT NULL,
    pin TEXT,
    status TEXT DEFAULT 'Clocked Out',
    active INTEGER DEFAULT 1,
    deleted_at DATETIME,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
  );

  CREATE TABLE IF NOT EXISTS clock_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    business_id TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('clock-in', 'clock-out')),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id)
  );

  CREATE TABLE IF NOT EXISTS payroll_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_id TEXT NOT NULL,
    employee_id INTEGER NOT NULL UNIQUE,
    hourly_rate REAL DEFAULT 0,
    filing_status TEXT DEFAULT 'single',
    allowances INTEGER DEFAULT 0,
    additional_withholding REAL DEFAULT 0,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (employee_id) REFERENCES employees(id)
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function requireAuth(req, res, next) {
  const sessionId = req.cookies.session;
  if (!sessionId) return res.status(401).json({ error: 'Unauthorized' });

  const session = db.prepare(
    'SELECT * FROM sessions WHERE id = ? AND expires_at > ?'
  ).get(sessionId, new Date().toISOString());

  if (!session) {
    res.clearCookie('session');
    return res.status(401).json({ error: 'Session expired' });
  }

  req.businessId = session.business_id;
  next();
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────

app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM businesses WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO businesses (id, name, email, password_hash) VALUES (?, ?, ?, ?)').run(id, name, email.toLowerCase(), hash);

  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (id, business_id, expires_at) VALUES (?, ?, ?)').run(sessionId, id, expiresAt);
  res.cookie('session', sessionId, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });

  res.json({ success: true });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required' });

  const business = db.prepare('SELECT * FROM businesses WHERE email = ?').get(email.toLowerCase());
  if (!business || !bcrypt.compareSync(password, business.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const sessionId = uuidv4();
  const expiresAt2 = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (id, business_id, expires_at) VALUES (?, ?, ?)').run(sessionId, business.id, expiresAt2);
  res.cookie('session', sessionId, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });

  res.json({ success: true });
});

app.post('/api/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(req.cookies.session);
  res.clearCookie('session');
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const business = db.prepare('SELECT id, name, email, created_at FROM businesses WHERE id = ?').get(req.businessId);
  res.json(business);
});

// ─── Employee Routes ──────────────────────────────────────────────────────────

app.get('/api/employees', requireAuth, (req, res) => {
  const employees = db.prepare(
    'SELECT id, name, status, active, pin IS NOT NULL as has_pin FROM employees WHERE business_id = ? AND deleted_at IS NULL ORDER BY name'
  ).all(req.businessId);
  res.json(employees);
});

app.post('/api/employees', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });

  const result = db.prepare(
    'INSERT INTO employees (business_id, name) VALUES (?, ?)'
  ).run(req.businessId, name.trim());

  res.json({ id: result.lastInsertRowid, name: name.trim(), status: 'Clocked Out', active: 1 });
});

app.patch('/api/employees/:id', requireAuth, (req, res) => {
  const emp = db.prepare('SELECT id FROM employees WHERE id = ? AND business_id = ?').get(req.params.id, req.businessId);
  if (!emp) return res.status(404).json({ error: 'Not found' });

  const { active } = req.body;
  if (typeof active === 'number') {
    db.prepare('UPDATE employees SET active = ? WHERE id = ?').run(active, req.params.id);
  }
  res.json({ success: true });
});

app.delete('/api/employees/:id', requireAuth, (req, res) => {
  const emp = db.prepare('SELECT id FROM employees WHERE id = ? AND business_id = ?').get(req.params.id, req.businessId);
  if (!emp) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE employees SET deleted_at = ? WHERE id = ?').run(new Date().toISOString(), req.params.id);
  res.json({ success: true });
});

app.post('/api/employees/:id/reset-pin', requireAuth, (req, res) => {
  const emp = db.prepare('SELECT id FROM employees WHERE id = ? AND business_id = ?').get(req.params.id, req.businessId);
  if (!emp) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE employees SET pin = NULL WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── Clock Routes (public, scoped by business slug/id) ───────────────────────

app.get('/api/clock/:businessId/employees', (req, res) => {
  const employees = db.prepare(
    'SELECT id, name, status FROM employees WHERE business_id = ? AND active = 1 AND deleted_at IS NULL ORDER BY name'
  ).all(req.params.businessId);
  res.json(employees);
});

app.post('/api/clock/:businessId/verify-pin', (req, res) => {
  const { employee_id, pin } = req.body;
  const emp = db.prepare(
    'SELECT * FROM employees WHERE id = ? AND business_id = ? AND active = 1 AND deleted_at IS NULL'
  ).get(employee_id, req.params.businessId);

  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (!emp.pin) return res.json({ needs_setup: true });
  if (emp.pin !== pin) return res.status(401).json({ error: 'Incorrect PIN' });

  res.json({ success: true, name: emp.name, status: emp.status });
});

app.post('/api/clock/:businessId/create-pin', (req, res) => {
  const { employee_id, pin } = req.body;
  if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be 4 digits' });
  }

  const emp = db.prepare(
    'SELECT * FROM employees WHERE id = ? AND business_id = ? AND active = 1 AND deleted_at IS NULL'
  ).get(employee_id, req.params.businessId);

  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (emp.pin) return res.status(400).json({ error: 'PIN already set' });

  db.prepare('UPDATE employees SET pin = ? WHERE id = ?').run(pin, employee_id);
  res.json({ success: true });
});

app.post('/api/clock/:businessId/clock', (req, res) => {
  const { employee_id, pin } = req.body;
  const emp = db.prepare(
    'SELECT * FROM employees WHERE id = ? AND business_id = ? AND active = 1 AND deleted_at IS NULL'
  ).get(employee_id, req.params.businessId);

  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (!emp.pin || emp.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });

  const type = emp.status === 'Clocked In' ? 'clock-out' : 'clock-in';
  const newStatus = type === 'clock-in' ? 'Clocked In' : 'Clocked Out';

  db.prepare('INSERT INTO clock_records (employee_id, business_id, type) VALUES (?, ?, ?)').run(employee_id, req.params.businessId, type);
  db.prepare('UPDATE employees SET status = ? WHERE id = ?').run(newStatus, employee_id);

  const timestamp = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  res.json({ success: true, type, status: newStatus, time: timestamp, name: emp.name });
});

// ─── Records Routes ───────────────────────────────────────────────────────────

app.get('/api/records', requireAuth, (req, res) => {
  const { start, end, employee_id } = req.query;
  let query = `
    SELECT r.id, r.type, r.timestamp, e.name as employee_name, e.id as employee_id
    FROM clock_records r
    JOIN employees e ON r.employee_id = e.id
    WHERE r.business_id = ?
  `;
  const params = [req.businessId];

  if (start) { query += ' AND r.timestamp >= ?'; params.push(start); }
  if (end) { query += ' AND r.timestamp <= ?'; params.push(end + ' 23:59:59'); }
  if (employee_id) { query += ' AND r.employee_id = ?'; params.push(employee_id); }

  query += ' ORDER BY r.timestamp DESC LIMIT 500';
  res.json(db.prepare(query).all(...params));
});

app.post('/api/records', requireAuth, (req, res) => {
  const { employee_id, type, timestamp } = req.body;
  const emp = db.prepare('SELECT id FROM employees WHERE id = ? AND business_id = ?').get(employee_id, req.businessId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });

  const result = db.prepare(
    'INSERT INTO clock_records (employee_id, business_id, type, timestamp) VALUES (?, ?, ?, ?)'
  ).run(employee_id, req.businessId, type, timestamp);

  res.json({ id: result.lastInsertRowid });
});

app.put('/api/records/:id', requireAuth, (req, res) => {
  const record = db.prepare('SELECT id FROM clock_records WHERE id = ? AND business_id = ?').get(req.params.id, req.businessId);
  if (!record) return res.status(404).json({ error: 'Not found' });

  const { type, timestamp } = req.body;
  db.prepare('UPDATE clock_records SET type = ?, timestamp = ? WHERE id = ?').run(type, timestamp, req.params.id);
  res.json({ success: true });
});

app.delete('/api/records/:id', requireAuth, (req, res) => {
  const record = db.prepare('SELECT id FROM clock_records WHERE id = ? AND business_id = ?').get(req.params.id, req.businessId);
  if (!record) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM clock_records WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── Payroll Settings ─────────────────────────────────────────────────────────

app.get('/api/payroll-settings', requireAuth, (req, res) => {
  const settings = db.prepare(
    'SELECT ps.*, e.name FROM payroll_settings ps JOIN employees e ON ps.employee_id = e.id WHERE ps.business_id = ?'
  ).all(req.businessId);
  res.json(settings);
});

app.post('/api/payroll-settings/:employeeId', requireAuth, (req, res) => {
  const emp = db.prepare('SELECT id FROM employees WHERE id = ? AND business_id = ?').get(req.params.employeeId, req.businessId);
  if (!emp) return res.status(404).json({ error: 'Not found' });

  const { hourly_rate, filing_status, allowances, additional_withholding } = req.body;
  db.prepare(`
    INSERT INTO payroll_settings (business_id, employee_id, hourly_rate, filing_status, allowances, additional_withholding)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(employee_id) DO UPDATE SET
      hourly_rate = excluded.hourly_rate,
      filing_status = excluded.filing_status,
      allowances = excluded.allowances,
      additional_withholding = excluded.additional_withholding
  `).run(req.businessId, req.params.employeeId, hourly_rate || 0, filing_status || 'single', allowances || 0, additional_withholding || 0);

  res.json({ success: true });
});

// ─── Payroll Calculation ──────────────────────────────────────────────────────

app.get('/api/payroll', requireAuth, (req, res) => {
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Start and end dates required' });

  const employees = db.prepare(
    'SELECT id, name FROM employees WHERE business_id = ? AND deleted_at IS NULL'
  ).all(req.businessId);

  const settings = {};
  db.prepare('SELECT * FROM payroll_settings WHERE business_id = ?').all(req.businessId).forEach(s => {
    settings[s.employee_id] = s;
  });

  const results = employees.map(emp => {
    const records = db.prepare(`
      SELECT type, timestamp FROM clock_records
      WHERE employee_id = ? AND business_id = ?
      AND timestamp >= ? AND timestamp <= ?
      ORDER BY timestamp ASC
    `).all(emp.id, req.businessId, start, end + ' 23:59:59');

    const s = settings[emp.id] || { hourly_rate: 0, filing_status: 'single', allowances: 0, additional_withholding: 0 };

    // Pair clock-in/out records and calculate hours per week
    const weeklyHours = {};
    let lastClockIn = null;

    for (const r of records) {
      if (r.type === 'clock-in') {
        lastClockIn = new Date(r.timestamp);
      } else if (r.type === 'clock-out' && lastClockIn) {
        const clockOut = new Date(r.timestamp);
        const hours = (clockOut - lastClockIn) / 3600000;
        const weekKey = getWeekKey(lastClockIn);
        weeklyHours[weekKey] = (weeklyHours[weekKey] || 0) + hours;
        lastClockIn = null;
      }
    }

    let regularHours = 0, overtimeHours = 0;
    for (const wk of Object.values(weeklyHours)) {
      if (wk > 40) { regularHours += 40; overtimeHours += wk - 40; }
      else { regularHours += wk; }
    }

    const regularPay = regularHours * s.hourly_rate;
    const overtimePay = overtimeHours * s.hourly_rate * 1.5;
    const grossPay = regularPay + overtimePay;

    // Simple federal tax estimate
    const federalTax = estimateFederalTax(grossPay, s.filing_status, s.allowances) + (s.additional_withholding || 0);
    const socialSecurity = grossPay * 0.062;
    const medicare = grossPay * 0.0145;
    const totalDeductions = federalTax + socialSecurity + medicare;
    const netPay = grossPay - totalDeductions;

    return {
      employee_id: emp.id,
      name: emp.name,
      regular_hours: Math.round(regularHours * 100) / 100,
      overtime_hours: Math.round(overtimeHours * 100) / 100,
      hourly_rate: s.hourly_rate,
      regular_pay: Math.round(regularPay * 100) / 100,
      overtime_pay: Math.round(overtimePay * 100) / 100,
      gross_pay: Math.round(grossPay * 100) / 100,
      federal_tax: Math.round(federalTax * 100) / 100,
      social_security: Math.round(socialSecurity * 100) / 100,
      medicare: Math.round(medicare * 100) / 100,
      net_pay: Math.round(netPay * 100) / 100,
    };
  });

  res.json(results);
});

function getWeekKey(date) {
  const d = new Date(date);
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(d.setDate(diff));
  return monday.toISOString().split('T')[0];
}

function estimateFederalTax(gross, filingStatus, allowances) {
  const allowanceValue = 4300 / 26; // biweekly allowance
  const taxableWages = Math.max(0, gross - allowances * allowanceValue);
  const brackets = filingStatus === 'married'
    ? [[0, 0], [654, 0.10], [2317, 0.12], [4815, 0.22], [9340, 0.24], [17533, 0.32], [22325, 0.35], [33502, 0.37]]
    : [[0, 0], [327, 0.10], [1158, 0.12], [2408, 0.22], [4670, 0.24], [8767, 0.32], [11163, 0.35], [16751, 0.37]];

  let tax = 0;
  for (let i = brackets.length - 1; i >= 0; i--) {
    if (taxableWages > brackets[i][0]) {
      tax = (taxableWages - brackets[i][0]) * brackets[i][1];
      for (let j = i - 1; j > 0; j--) {
        tax += (brackets[j][0] - brackets[j - 1][0]) * brackets[j][1];
      }
      break;
    }
  }
  return Math.max(0, tax);
}

// ─── Dashboard stats ──────────────────────────────────────────────────────────

app.get('/api/stats', requireAuth, (req, res) => {
  const totalEmployees = db.prepare('SELECT COUNT(*) as count FROM employees WHERE business_id = ? AND active = 1 AND deleted_at IS NULL').get(req.businessId).count;
  const clockedIn = db.prepare('SELECT COUNT(*) as count FROM employees WHERE business_id = ? AND status = "Clocked In" AND active = 1 AND deleted_at IS NULL').get(req.businessId).count;
  const todayRecords = db.prepare("SELECT COUNT(*) as count FROM clock_records WHERE business_id = ? AND date(timestamp) = date('now')").get(req.businessId).count;

  res.json({ totalEmployees, clockedIn, todayRecords });
});

// ─── Page Routes ─────────────────────────────────────────────────────────────

// Root redirects to login (landing page is commented out in public/index.html)
app.get('/', (req, res) => {
  const sessionId = req.cookies.session;
  if (sessionId) {
    const session = db.prepare('SELECT id FROM sessions WHERE id = ? AND expires_at > ?').get(sessionId, new Date().toISOString());
    if (session) return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

app.get('/dashboard', (req, res) => {
  const sessionId = req.cookies.session;
  if (!sessionId) return res.redirect('/login');
  const session = db.prepare('SELECT id FROM sessions WHERE id = ? AND expires_at > ?').get(sessionId, new Date().toISOString());
  if (!session) { res.clearCookie('session'); return res.redirect('/login'); }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Public clock-in page — no auth required, scoped by businessId
app.get('/clock/:businessId', (req, res) => {
  const biz = db.prepare('SELECT id FROM businesses WHERE id = ?').get(req.params.businessId);
  if (!biz) return res.status(404).send('Business not found');
  res.sendFile(path.join(__dirname, 'public', 'clock.html'));
});

app.get('/login', (req, res) => {
  const sessionId = req.cookies.session;
  if (sessionId) {
    const session = db.prepare('SELECT id FROM sessions WHERE id = ? AND expires_at > ?').get(sessionId, new Date().toISOString());
    if (session) return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  const sessionId = req.cookies.session;
  if (sessionId) {
    const session = db.prepare('SELECT id FROM sessions WHERE id = ? AND expires_at > ?').get(sessionId, new Date().toISOString());
    if (session) return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.listen(PORT, () => console.log(`Tempo running on http://localhost:${PORT}`));
