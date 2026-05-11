require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const cookieSession = require('cookie-session');
const { createClient } = require('@libsql/client');
const { Resend } = require('resend');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
  name: 'session',
  secret: process.env.SESSION_SECRET || 'oil-change-default-secret-change-me',
  maxAge: 8 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

// ─── Database ─────────────────────────────────────────────────────────────────
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:local.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const toObj = (row, cols) => {
  if (!row) return null;
  const o = {};
  cols.forEach((c, i) => { o[c] = row[i]; });
  return o;
};

const dbGet = async (sql, args = []) => {
  const r = await db.execute({ sql, args });
  return toObj(r.rows[0], r.columns);
};
const dbAll = async (sql, args = []) => {
  const r = await db.execute({ sql, args });
  return r.rows.map(row => toObj(row, r.columns));
};
const dbRun = async (sql, args = []) => {
  const r = await db.execute({ sql, args });
  return { lastInsertRowid: Number(r.lastInsertRowid) };
};
const dbExec = (sql) => db.execute({ sql, args: [] });

const dbReady = (async () => {
  await dbExec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT DEFAULT '',
    password_hash TEXT NOT NULL, zip_code TEXT DEFAULT '',
    address_street TEXT DEFAULT '', address_number TEXT DEFAULT '', address_city TEXT DEFAULT '',
    role TEXT DEFAULT 'customer',
    reset_token TEXT DEFAULT NULL, reset_expires TEXT DEFAULT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await dbExec(`CREATE TABLE IF NOT EXISTS vehicles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    vehicle TEXT NOT NULL, oil_type TEXT DEFAULT 'Convencional',
    location TEXT DEFAULT '', notes TEXT DEFAULT '', color TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await dbExec(`CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER DEFAULT NULL, vehicle_id INTEGER DEFAULT NULL,
    name TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT NOT NULL,
    vehicle TEXT NOT NULL, oil_type TEXT DEFAULT 'Convencional',
    date TEXT NOT NULL, time TEXT NOT NULL, notes TEXT DEFAULT '', location TEXT DEFAULT '',
    is_recurring INTEGER DEFAULT 0, recurrence_weeks INTEGER DEFAULT 12,
    parent_id INTEGER DEFAULT NULL, status TEXT DEFAULT 'pending',
    mileage INTEGER DEFAULT NULL, technician_id INTEGER DEFAULT NULL,
    tire_fl INTEGER DEFAULT NULL, tire_fr INTEGER DEFAULT NULL,
    tire_rl INTEGER DEFAULT NULL, tire_rr INTEGER DEFAULT NULL,
    brake_front INTEGER DEFAULT NULL, brake_rear INTEGER DEFAULT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await dbExec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT DEFAULT '')`);
  await dbExec(`CREATE TABLE IF NOT EXISTS vehicle_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL,
    vehicle TEXT DEFAULT '', tire_fl INTEGER DEFAULT NULL, tire_fr INTEGER DEFAULT NULL,
    tire_rl INTEGER DEFAULT NULL, tire_rr INTEGER DEFAULT NULL,
    brake_front INTEGER DEFAULT NULL, brake_rear INTEGER DEFAULT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP, appointment_id INTEGER DEFAULT NULL
  )`);
  for (const sql of [
    "ALTER TABLE users ADD COLUMN zip_code TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN address_street TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN address_number TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN address_city TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'customer'",
    "ALTER TABLE users ADD COLUMN reset_token TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN reset_expires TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN verification_token TEXT DEFAULT NULL",
    "ALTER TABLE vehicles ADD COLUMN color TEXT DEFAULT ''",
    "ALTER TABLE appointments ADD COLUMN user_id INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN vehicle_id INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN location TEXT DEFAULT ''",
    "ALTER TABLE appointments ADD COLUMN mileage INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN technician_id INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN tire_fl INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN tire_fr INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN tire_rl INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN tire_rr INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN brake_front INTEGER DEFAULT NULL",
    "ALTER TABLE appointments ADD COLUMN brake_rear INTEGER DEFAULT NULL",
  ]) { try { await dbExec(sql); } catch {} }
  try { await dbExec("UPDATE users SET email_verified=1 WHERE verification_token IS NULL AND email_verified=0"); } catch {}
  await buildSendGrid();
})();

app.use(async (_req, _res, next) => { try { await dbReady; next(); } catch (e) { next(e); } });

// ─── Password helpers ─────────────────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(password, salt, 64).toString('hex') === hash;
}

// ─── Email (Resend) ───────────────────────────────────────────────────────────
let resendClient = null;
let sgConfigured = false;

const DEFAULT_TEMPLATES = {
  appointment_confirmed: {
    subject: '✅ Cita confirmada – [fecha] a las [hora]',
    body: `Hola [nombre del cliente], tu cita ha sido registrada con éxito.\n\nFecha: [fecha] a las [hora]\nVehículo: [vehículo]\nTipo de aceite: [tipo de aceite]\n[dirección]\n[notas]`
  },
  email_verification: {
    subject: '✉️ Confirma tu correo electrónico',
    body: `Hola [nombre del cliente],\n\nGracias por registrarte. Haz clic en el siguiente enlace para confirmar tu correo y activar tu cuenta:\n\n[enlace de verificación]\n\nSi no creaste una cuenta, ignora este correo.`
  },
  forgot_password: {
    subject: '🔑 Recupera tu contraseña',
    body: `Hola [nombre del cliente],\n\nRecibimos una solicitud para restablecer tu contraseña. El enlace es válido por 1 hora.\n\n[enlace de recuperación]\n\nSi no solicitaste esto, ignora este correo.`
  }
};

function wrapEmailHtml(type, text) {
  const meta = {
    appointment_confirmed: { icon: '🛢️', title: '¡Cita Confirmada!' },
    forgot_password:       { icon: '🔑', title: 'Restablecer contraseña' },
    email_verification:    { icon: '✉️', title: 'Confirma tu correo' },
  };
  const { icon, title } = meta[type] || { icon: '📧', title: 'Mensaje' };
  const inner = text.split('\n').map(line => {
    const t = line.trim();
    if (!t) return '<div style="height:6px"></div>';
    if (t.startsWith('http://') || t.startsWith('https://'))
      return `<div style="text-align:center;margin:16px 0"><a href="${t}" style="display:inline-block;background:linear-gradient(135deg,#CC2936,#A31F2B);color:white;padding:13px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">Abrir enlace</a></div>`;
    return `<p style="font-size:15px;color:#333;margin:0 0 10px;line-height:1.5">${t}</p>`;
  }).join('');
  return `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;border-radius:16px;overflow:hidden"><div style="background:linear-gradient(135deg,#CC2936,#A31F2B);padding:32px;text-align:center"><div style="font-size:48px">${icon}</div><h1 style="color:white;font-size:22px;margin:12px 0 0;font-family:Arial,sans-serif">${title}</h1></div><div style="background:#f8f9fa;padding:28px;border:1px solid #e9ecef;border-top:none;border-radius:0 0 16px 16px">${inner}<p style="text-align:center;font-size:12px;color:#999;margin:16px 0 0">¡Gracias por tu preferencia!</p></div></div>`;
}

async function getSetting(key) {
  const row = await dbGet('SELECT value FROM settings WHERE key=?', [key]);
  return row?.value || '';
}
async function setSetting(key, value) {
  await dbRun('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [key, value]);
}

async function buildSendGrid() {
  const key = await getSetting('sg_api_key') || process.env.RESEND_API_KEY || '';
  if (key.trim()) { resendClient = new Resend(key.trim()); sgConfigured = true; return true; }
  resendClient = null; sgConfigured = false; return false;
}

async function renderTemplate(type, vars) {
  const tpl = DEFAULT_TEMPLATES[type] || { subject: '', body: '' };
  let subject = await getSetting(`tpl_${type}_subject`) || tpl.subject;
  let body    = await getSetting(`tpl_${type}_body`)    || tpl.body;
  const friendly = {
    '[nombre del cliente]': vars.name, '[fecha]': vars.date, '[hora]': vars.time,
    '[vehículo]': vars.vehicle, '[tipo de aceite]': vars.oil_type,
    '[dirección]': vars.location, '[notas]': vars.notes,
    '[enlace de recuperación]': vars.resetLink, '[enlace de verificación]': vars.verifyLink,
  };
  const replace = s => {
    for (const [k, v] of Object.entries(friendly)) {
      if (v !== undefined && v !== null) s = s.split(k).join(v);
    }
    return s.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] !== undefined ? vars[k] : '');
  };
  const renderedSubject = replace(subject);
  let renderedBody = replace(body);
  if (!renderedBody.trim().startsWith('<')) renderedBody = wrapEmailHtml(type, renderedBody);
  return { subject: renderedSubject, body: renderedBody };
}

async function sendEmail(to, type, vars) {
  if (!resendClient) return false;
  const fromEmail = await getSetting('sg_from_email') || process.env.RESEND_FROM || 'onboarding@resend.dev';
  const fromName  = await getSetting('sg_from_name')  || 'Cambio de Aceite';
  const { subject, body } = await renderTemplate(type, vars);
  try {
    const { error } = await resendClient.emails.send({ from: `${fromName} <${fromEmail}>`, to, subject, html: body });
    if (error) { console.error('Resend error:', error.message); return false; }
    return true;
  } catch(e) { console.error('Resend error:', e.message); return false; }
}

async function sendConfirmation(appt) {
  if (!appt.email) return;
  const d = new Date(appt.date + 'T00:00:00');
  const dateStr = d.toLocaleDateString('es-MX', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  await sendEmail(appt.email, 'appointment_confirmed', {
    name: appt.name || '', date: dateStr, time: appt.time || '',
    vehicle: appt.vehicle || '', oil_type: appt.oil_type || '',
    location: appt.location ? `📍 ${appt.location}` : '',
    notes:    appt.notes    ? `📝 ${appt.notes}` : '',
    location_row: appt.location ? `<p style="margin:0 0 10px;font-size:14px;color:#555">📍 ${appt.location}</p>` : '',
    notes_row:    appt.notes    ? `<p style="margin:0;font-size:14px;color:#555">📝 ${appt.notes}</p>` : '',
  });
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
const requireAdmin = (req, res, next) => {
  if (req.session?.authenticated) return next();
  if (req.path.startsWith('/api/admin')) return res.status(401).json({ error: 'No autorizado' });
  res.redirect('/login');
};
const requireCustomer = (req, res, next) => {
  if (req.session?.customerId) return next();
  if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ error: 'No autenticado' });
  res.redirect('/auth');
};
const requireTech = (req, res, next) => {
  if (req.session?.customerId && req.session?.customerRole === 'technician') return next();
  if (req.originalUrl.startsWith('/api/tech')) return res.status(401).json({ error: 'No autorizado' });
  res.redirect('/tech-login');
};

// ─── Route protection ─────────────────────────────────────────────────────────
app.get('/', requireCustomer, (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/technician', requireTech, (_req, res) => res.sendFile(path.join(__dirname, 'views', 'technician.html')));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Customer auth routes ─────────────────────────────────────────────────────
app.get('/auth', (req, res) => {
  if (req.session?.customerId) return res.redirect(req.session.customerRole === 'technician' ? '/technician' : '/');
  res.sendFile(path.join(__dirname, 'views', 'auth.html'));
});
app.get('/tech-login', (req, res) => {
  if (req.session?.customerId && req.session?.customerRole === 'technician') return res.redirect('/technician');
  res.sendFile(path.join(__dirname, 'views', 'tech-login.html'));
});

app.post('/auth/register', async (req, res) => {
  const { name, email, phone, password, confirm } = req.body;
  if (!name || !email || !password) return res.redirect('/auth?tab=register&error=campos');
  if (password !== confirm) return res.redirect('/auth?tab=register&error=password');
  if (password.length < 6) return res.redirect('/auth?tab=register&error=corta');
  const exists = await dbGet('SELECT id FROM users WHERE email=?', [email.toLowerCase()]);
  if (exists) return res.redirect('/auth?tab=register&error=email');
  const vtoken = crypto.randomBytes(32).toString('hex');
  const r = await dbRun(
    'INSERT INTO users (name,email,phone,password_hash,verification_token,email_verified) VALUES (?,?,?,?,?,0)',
    [name.trim(), email.toLowerCase(), phone || '', hashPassword(password), vtoken]
  );
  const verifyUrl = `${req.protocol}://${req.get('host')}/auth/verify-email?token=${vtoken}`;
  await sendEmail(email.toLowerCase(), 'email_verification', { name: name.trim(), verifyLink: verifyUrl });
  req.session.customerId = r.lastInsertRowid;
  req.session.customerName = name.trim();
  req.session.customerRole = 'customer';
  res.redirect('/');
});

app.post('/auth/login', async (req, res) => {
  const { email, password, role_hint } = req.body;
  const isTechLogin = role_hint === 'technician';
  const user = await dbGet('SELECT * FROM users WHERE email=?', [email?.toLowerCase() || '']);
  if (!user || !verifyPassword(password || '', user.password_hash))
    return res.redirect(isTechLogin ? '/tech-login?error=credenciales' : '/auth?tab=login&error=credenciales');
  if (isTechLogin && user.role !== 'technician') return res.redirect('/tech-login?error=norole');
  req.session.customerId = Number(user.id);
  req.session.customerName = user.name;
  req.session.customerRole = user.role || 'customer';
  res.redirect(user.role === 'technician' ? '/technician' : '/');
});

app.get('/auth/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/auth?verified=error');
  const user = await dbGet('SELECT id, name FROM users WHERE verification_token=?', [token]);
  if (!user) return res.redirect('/auth?verified=error');
  await dbRun('UPDATE users SET email_verified=1, verification_token=NULL WHERE id=?', [Number(user.id)]);
  req.session.customerId = Number(user.id);
  req.session.customerName = user.name;
  req.session.customerRole = 'customer';
  res.redirect('/');
});

app.post('/api/me/resend-verification', requireCustomer, async (req, res) => {
  const user = await dbGet("SELECT id,name,email,email_verified FROM users WHERE id=?", [req.session.customerId]);
  if (!user || user.email_verified) return res.json({ success: true });
  const vtoken = crypto.randomBytes(32).toString('hex');
  await dbRun('UPDATE users SET verification_token=? WHERE id=?', [vtoken, req.session.customerId]);
  const verifyUrl = `${req.protocol}://${req.get('host')}/auth/verify-email?token=${vtoken}`;
  await sendEmail(user.email, 'email_verification', { name: user.name, verifyLink: verifyUrl });
  res.json({ success: true });
});

app.post('/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.redirect('/auth?tab=login&verify=sent');
  const user = await dbGet("SELECT id, name FROM users WHERE email=? AND email_verified=0 AND role='customer'", [email.toLowerCase()]);
  if (user) {
    const vtoken = crypto.randomBytes(32).toString('hex');
    await dbRun('UPDATE users SET verification_token=? WHERE id=?', [vtoken, Number(user.id)]);
    const verifyUrl = `${req.protocol}://${req.get('host')}/auth/verify-email?token=${vtoken}`;
    await sendEmail(email.toLowerCase(), 'email_verification', { name: user.name, verifyLink: verifyUrl });
  }
  res.redirect('/auth?tab=login&verify=sent');
});

app.get('/auth/logout', (req, res) => { req.session = null; res.redirect('/auth'); });

// ─── Customer API ─────────────────────────────────────────────────────────────
app.get('/api/me', requireCustomer, async (req, res) => {
  const user = await dbGet('SELECT id,name,email,phone,zip_code,address_street,address_number,address_city,email_verified FROM users WHERE id=?', [req.session.customerId]);
  res.json(user || {});
});

app.delete('/api/me', requireCustomer, async (req, res) => {
  const uid = req.session.customerId;
  await dbRun("UPDATE appointments SET status='cancelled' WHERE user_id=? AND status='pending'", [uid]);
  await dbRun('DELETE FROM vehicles WHERE user_id=?', [uid]);
  await dbRun('DELETE FROM vehicle_health WHERE user_id=?', [uid]);
  await dbRun('DELETE FROM users WHERE id=?', [uid]);
  req.session = null;
  res.json({ success: true });
});

app.put('/api/me/address', requireCustomer, async (req, res) => {
  const { address_street, address_number, address_city, zip_code } = req.body;
  if (!address_street?.trim() || !address_city?.trim() || !zip_code?.trim())
    return res.status(400).json({ error: 'Calle, ciudad y código postal son requeridos' });
  await dbRun('UPDATE users SET address_street=?,address_number=?,address_city=?,zip_code=? WHERE id=?',
    [address_street.trim(), (address_number||'').trim(), address_city.trim(), zip_code.trim(), req.session.customerId]);
  res.json({ success: true });
});

app.put('/api/me/zip', requireCustomer, async (req, res) => {
  const { zip_code } = req.body;
  if (!zip_code?.trim()) return res.status(400).json({ error: 'ZIP requerido' });
  await dbRun('UPDATE users SET zip_code=? WHERE id=?', [zip_code.trim(), req.session.customerId]);
  res.json({ success: true });
});

// Vehicles
app.get('/api/vehicles', requireCustomer, async (req, res) => {
  res.json(await dbAll('SELECT * FROM vehicles WHERE user_id=? ORDER BY created_at ASC', [req.session.customerId]));
});

app.post('/api/vehicles', requireCustomer, async (req, res) => {
  const { vehicle, oil_type, location, notes, color } = req.body;
  if (!vehicle?.trim()) return res.status(400).json({ error: 'Vehículo requerido' });
  const r = await dbRun('INSERT INTO vehicles (user_id,vehicle,oil_type,location,notes,color) VALUES (?,?,?,?,?,?)',
    [req.session.customerId, vehicle.trim(), oil_type || 'Convencional', location || '', notes || '', color || '']);
  res.json({ success: true, vehicle: await dbGet('SELECT * FROM vehicles WHERE id=?', [r.lastInsertRowid]) });
});

app.delete('/api/vehicles/:id', requireCustomer, async (req, res) => {
  const v = await dbGet('SELECT id FROM vehicles WHERE id=? AND user_id=?', [+req.params.id, req.session.customerId]);
  if (!v) return res.status(404).json({ error: 'No encontrado' });
  await dbRun('DELETE FROM vehicles WHERE id=?', [+req.params.id]);
  res.json({ success: true });
});

app.get('/api/vehicles/:id/history', requireCustomer, async (req, res) => {
  const v = await dbGet('SELECT id FROM vehicles WHERE id=? AND user_id=?', [+req.params.id, req.session.customerId]);
  if (!v) return res.status(404).json({ error: 'No encontrado' });
  res.json(await dbAll("SELECT * FROM appointments WHERE vehicle_id=? AND status='completed' ORDER BY date DESC, time DESC", [+req.params.id]));
});

app.get('/api/vehicles/:id/appointments', requireCustomer, async (req, res) => {
  const v = await dbGet('SELECT id FROM vehicles WHERE id=? AND user_id=?', [+req.params.id, req.session.customerId]);
  if (!v) return res.status(404).json({ error: 'No encontrado' });
  const today = new Date().toISOString().split('T')[0];
  res.json(await dbAll("SELECT * FROM appointments WHERE vehicle_id=? AND date>=? AND status='pending' ORDER BY date,time", [+req.params.id, today]));
});

app.get('/api/my-appointments', requireCustomer, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.json(await dbAll("SELECT * FROM appointments WHERE user_id=? AND date>=? AND status='pending' ORDER BY date,time", [req.session.customerId, today]));
});

const TIME_SLOTS = ['8:00','9:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00'];

app.get('/api/appointments/available-slots', requireCustomer, async (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: 'Date required' });
  const taken = (await dbAll("SELECT time FROM appointments WHERE date=? AND status='pending'", [date])).map(r => r.time);
  res.json({ available: TIME_SLOTS.filter(s => !taken.includes(s)), taken });
});

app.post('/api/appointments', requireCustomer, async (req, res) => {
  const u = await dbGet('SELECT email_verified FROM users WHERE id=?', [req.session.customerId]);
  if (u && !u.email_verified) return res.status(403).json({ error: 'verify_email' });
  const { name, email, phone, vehicle, oil_type, date, time, notes, location, is_recurring, recurrence_weeks, vehicle_id } = req.body;
  if (!name || !phone || !vehicle || !date || !time || !location)
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate() + 1);
  if (date < tomorrow.toISOString().split('T')[0])
    return res.status(400).json({ error: 'Las citas deben agendarse con al menos 1 día de anticipación' });
  const exists = await dbGet("SELECT id FROM appointments WHERE date=? AND time=? AND status='pending'", [date, time]);
  if (exists) return res.status(409).json({ error: 'Ese horario ya está reservado' });
  const r = await dbRun(
    `INSERT INTO appointments (user_id,vehicle_id,name,email,phone,vehicle,oil_type,date,time,notes,location,is_recurring,recurrence_weeks)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [req.session.customerId, vehicle_id || null, name, email || '', phone, vehicle,
     oil_type || 'Convencional', date, time, notes || '', location, is_recurring ? 1 : 0, recurrence_weeks || 12]
  );
  const appt = await dbGet('SELECT a.*, v.color as vehicle_color FROM appointments a LEFT JOIN vehicles v ON a.vehicle_id=v.id WHERE a.id=?', [r.lastInsertRowid]);
  sendConfirmation(appt);
  res.json({ success: true, id: r.lastInsertRowid });
});

app.delete('/api/my-appointments/:id', requireCustomer, async (req, res) => {
  const appt = await dbGet('SELECT id FROM appointments WHERE id=? AND user_id=?', [+req.params.id, req.session.customerId]);
  if (!appt) return res.status(404).json({ error: 'No encontrado' });
  await dbRun("UPDATE appointments SET status='cancelled' WHERE id=?", [+req.params.id]);
  res.json({ success: true });
});

// ─── Admin auth routes ────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session?.authenticated) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === (process.env.ADMIN_USER || 'admin') && password === (process.env.ADMIN_PASSWORD || 'admin123')) {
    req.session.authenticated = true;
    return res.redirect('/admin');
  }
  res.redirect('/login?error=1');
});
app.get('/logout', (req, res) => { req.session = null; res.redirect('/login'); });
app.get('/admin', requireAdmin, (_req, res) => res.sendFile(path.join(__dirname, 'views', 'admin.html')));

// ─── Admin API ────────────────────────────────────────────────────────────────
app.get('/api/admin/appointments/upcoming', requireAdmin, async (_req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const end = new Date(); end.setDate(end.getDate() + 14);
  res.json(await dbAll(
    `SELECT a.*, t.name as technician_name, v.color as vehicle_color FROM appointments a
     LEFT JOIN users t ON a.technician_id = t.id LEFT JOIN vehicles v ON a.vehicle_id = v.id
     WHERE a.date>=? AND a.date<=? AND a.status='pending' ORDER BY a.date,a.time`,
    [today, end.toISOString().split('T')[0]]
  ));
});

app.get('/api/admin/appointments', requireAdmin, async (_req, res) => {
  res.json(await dbAll(
    `SELECT a.*, u.email as user_email, t.name as technician_name, v.color as vehicle_color FROM appointments a
     LEFT JOIN users u ON a.user_id = u.id LEFT JOIN users t ON a.technician_id = t.id
     LEFT JOIN vehicles v ON a.vehicle_id = v.id ORDER BY a.date DESC, a.time ASC`
  ));
});

app.get('/api/admin/stats', requireAdmin, async (_req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const d7 = new Date(); d7.setDate(d7.getDate() + 7);
  const d14 = new Date(); d14.setDate(d14.getDate() + 14);
  const [r1,r2,r3,r4,r5,r6] = await Promise.all([
    dbGet("SELECT COUNT(*) c FROM appointments WHERE date=? AND status='pending'", [today]),
    dbGet("SELECT COUNT(*) c FROM appointments WHERE date>=? AND date<=? AND status='pending'", [today, d7.toISOString().split('T')[0]]),
    dbGet("SELECT COUNT(*) c FROM appointments WHERE date>=? AND date<=? AND status='pending'", [today, d14.toISOString().split('T')[0]]),
    dbGet("SELECT COUNT(*) c FROM appointments WHERE status='pending'"),
    dbGet("SELECT COUNT(*) c FROM users WHERE role='customer'"),
    dbGet("SELECT COUNT(*) c FROM users WHERE role='technician'"),
  ]);
  res.json({ today: Number(r1.c), week: Number(r2.c), twoWeeks: Number(r3.c), pending: Number(r4.c), customers: Number(r5.c), technicians: Number(r6.c) });
});

app.put('/api/admin/appointments/:id/complete', requireAdmin, async (req, res) => {
  const appt = await dbGet('SELECT * FROM appointments WHERE id=?', [+req.params.id]);
  if (!appt) return res.status(404).json({ error: 'Not found' });
  if (appt.status === 'completed') return res.status(409).json({ error: 'Ya completada' });
  const { tire_fl, tire_fr, tire_rl, tire_rr, brake_front, brake_rear, mileage } = req.body || {};
  await dbRun(`UPDATE appointments SET status='completed', mileage=?,
    tire_fl=?, tire_fr=?, tire_rl=?, tire_rr=?, brake_front=?, brake_rear=? WHERE id=?`,
    [mileage??null,tire_fl??null,tire_fr??null,tire_rl??null,tire_rr??null,brake_front??null,brake_rear??null,Number(appt.id)]);
  const hasHealth = [tire_fl,tire_fr,tire_rl,tire_rr,brake_front,brake_rear].some(v => v != null);
  if (appt.user_id && hasHealth) {
    await dbRun(`INSERT INTO vehicle_health (user_id,vehicle,tire_fl,tire_fr,tire_rl,tire_rr,brake_front,brake_rear,updated_at,appointment_id)
      VALUES (?,?,?,?,?,?,?,?,datetime('now'),?)
      ON CONFLICT(user_id) DO UPDATE SET vehicle=excluded.vehicle,
        tire_fl=excluded.tire_fl,tire_fr=excluded.tire_fr,tire_rl=excluded.tire_rl,tire_rr=excluded.tire_rr,
        brake_front=excluded.brake_front,brake_rear=excluded.brake_rear,
        updated_at=excluded.updated_at,appointment_id=excluded.appointment_id`,
      [Number(appt.user_id),appt.vehicle,tire_fl??null,tire_fr??null,tire_rl??null,tire_rr??null,brake_front??null,brake_rear??null,Number(appt.id)]);
  }
  let nextDate = null, nextId = null;
  if (appt.is_recurring) {
    const d = new Date(appt.date + 'T00:00:00');
    d.setDate(d.getDate() + appt.recurrence_weeks * 7);
    nextDate = d.toISOString().split('T')[0];
    const r = await dbRun(
      `INSERT INTO appointments (user_id,vehicle_id,name,email,phone,vehicle,oil_type,date,time,notes,location,is_recurring,recurrence_weeks,parent_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)`,
      [appt.user_id,appt.vehicle_id,appt.name,appt.email,appt.phone,appt.vehicle,appt.oil_type,
       nextDate,appt.time,appt.notes,appt.location||'',appt.recurrence_weeks,Number(appt.id)]
    );
    nextId = r.lastInsertRowid;
    sendConfirmation({ ...appt, date: nextDate, id: nextId });
  }
  res.json({ success: true, nextId, nextDate });
});

app.put('/api/admin/appointments/:id/assign', requireAdmin, async (req, res) => {
  const { technician_id } = req.body;
  await dbRun('UPDATE appointments SET technician_id=? WHERE id=?', [technician_id || null, +req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/appointments/:id', requireAdmin, async (req, res) => {
  await dbRun("UPDATE appointments SET status='cancelled' WHERE id=?", [+req.params.id]);
  res.json({ success: true });
});

app.post('/api/admin/appointments', requireAdmin, async (req, res) => {
  const { name, phone, email, vehicle, oil_type, date, time, notes, location, user_id, vehicle_id, technician_id } = req.body;
  if (!name || !phone || !vehicle || !date || !time)
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate() + 1);
  if (date < tomorrow.toISOString().split('T')[0])
    return res.status(400).json({ error: 'Mínimo 1 día de anticipación' });
  const exists = await dbGet("SELECT id FROM appointments WHERE date=? AND time=? AND status='pending'", [date, time]);
  if (exists) return res.status(409).json({ error: 'Horario ya reservado' });
  const r = await dbRun(
    `INSERT INTO appointments (user_id,vehicle_id,name,email,phone,vehicle,oil_type,date,time,notes,location,technician_id)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    [user_id||null,vehicle_id||null,name,email||'',phone,vehicle,oil_type||'Convencional',
     date,time,notes||'',location||'',technician_id||null]
  );
  const appt = await dbGet('SELECT a.*, v.color as vehicle_color FROM appointments a LEFT JOIN vehicles v ON a.vehicle_id=v.id WHERE a.id=?', [r.lastInsertRowid]);
  sendConfirmation(appt);
  res.json({ success: true, id: r.lastInsertRowid });
});

app.get('/api/admin/technicians', requireAdmin, async (_req, res) => {
  res.json(await dbAll("SELECT id,name,email,phone,created_at FROM users WHERE role='technician' ORDER BY name"));
});
app.post('/api/admin/technicians', requireAdmin, async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Faltan campos' });
  if (await dbGet('SELECT id FROM users WHERE email=?', [email.toLowerCase()]))
    return res.status(409).json({ error: 'Email ya registrado' });
  const r = await dbRun("INSERT INTO users (name,email,phone,password_hash,role) VALUES (?,?,?,?,'technician')",
    [name.trim(), email.toLowerCase(), phone||'', hashPassword(password)]);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.delete('/api/admin/technicians/:id', requireAdmin, async (req, res) => {
  await dbRun("DELETE FROM users WHERE id=? AND role='technician'", [+req.params.id]);
  res.json({ success: true });
});
app.put('/api/admin/technicians/:id/password', requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Mínimo 6 caracteres' });
  const tech = await dbGet("SELECT id FROM users WHERE id=? AND role='technician'", [+req.params.id]);
  if (!tech) return res.status(404).json({ error: 'No encontrado' });
  await dbRun('UPDATE users SET password_hash=? WHERE id=?', [hashPassword(password), +req.params.id]);
  res.json({ success: true });
});

// ─── Email settings ───────────────────────────────────────────────────────────
app.get('/api/admin/settings/sendgrid', requireAdmin, async (_req, res) => {
  const apiKeySet = !!(await getSetting('sg_api_key') || process.env.RESEND_API_KEY);
  res.json({
    api_key_set: apiKeySet,
    from_email: await getSetting('sg_from_email') || process.env.RESEND_FROM || '',
    from_name:  await getSetting('sg_from_name')  || 'Cambio de Aceite',
    configured: sgConfigured,
  });
});
app.put('/api/admin/settings/sendgrid', requireAdmin, async (req, res) => {
  const { api_key, from_email, from_name } = req.body;
  if (!from_email?.trim()) return res.status(400).json({ error: 'El correo de envío es requerido' });
  if (api_key?.trim()) await setSetting('sg_api_key', api_key.trim());
  await setSetting('sg_from_email', from_email.trim());
  await setSetting('sg_from_name', (from_name || 'Cambio de Aceite').trim());
  await buildSendGrid();
  res.json({ success: true, configured: sgConfigured });
});
app.post('/api/admin/settings/sendgrid/test', requireAdmin, async (_req, res) => {
  const to = await getSetting('sg_from_email') || process.env.RESEND_FROM || '';
  if (!to) return res.status(400).json({ error: 'Configura el correo de envío primero' });
  const ok = await sendEmail(to, 'appointment_confirmed', {
    name: 'Admin (prueba)', date: 'Lunes 1 de enero', time: '10:00 AM',
    vehicle: 'Toyota Camry 2022', oil_type: 'Sintético — $85', location_row: '', notes_row: '',
  });
  res.json({ success: ok, error: ok ? null : 'No se pudo enviar. Verifica la API key y el correo de envío.' });
});

// ─── Email templates ──────────────────────────────────────────────────────────
const TEMPLATE_TYPES = ['appointment_confirmed', 'forgot_password', 'email_verification'];

app.get('/api/admin/email-templates', requireAdmin, async (_req, res) => {
  const result = {};
  for (const type of TEMPLATE_TYPES) {
    const s = await getSetting(`tpl_${type}_subject`);
    const b = await getSetting(`tpl_${type}_body`);
    result[type] = {
      subject: s || DEFAULT_TEMPLATES[type].subject,
      body:    b || DEFAULT_TEMPLATES[type].body,
      is_custom: !!(s || b),
    };
  }
  res.json(result);
});
app.put('/api/admin/email-templates/:type', requireAdmin, async (req, res) => {
  const { type } = req.params;
  if (!TEMPLATE_TYPES.includes(type)) return res.status(400).json({ error: 'Tipo inválido' });
  const { subject, body } = req.body;
  if (!subject?.trim() || !body?.trim()) return res.status(400).json({ error: 'Asunto y cuerpo son requeridos' });
  await setSetting(`tpl_${type}_subject`, subject.trim());
  await setSetting(`tpl_${type}_body`, body.trim());
  res.json({ success: true });
});
app.delete('/api/admin/email-templates/:type', requireAdmin, async (req, res) => {
  const { type } = req.params;
  if (!TEMPLATE_TYPES.includes(type)) return res.status(400).json({ error: 'Tipo inválido' });
  await dbRun("DELETE FROM settings WHERE key=?", [`tpl_${type}_subject`]);
  await dbRun("DELETE FROM settings WHERE key=?", [`tpl_${type}_body`]);
  res.json({ success: true, default: DEFAULT_TEMPLATES[type] });
});

app.get('/api/admin/customers', requireAdmin, async (_req, res) => {
  res.json(await dbAll("SELECT id,name,email,phone FROM users WHERE role='customer' ORDER BY name"));
});

// ─── Technician API ───────────────────────────────────────────────────────────
app.get('/api/tech/me', requireTech, async (req, res) => {
  res.json(await dbGet('SELECT id,name,email,phone FROM users WHERE id=?', [req.session.customerId]) || {});
});
app.get('/api/tech/appointments', requireTech, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.json(await dbAll(
    `SELECT a.*, v.color as vehicle_color FROM appointments a LEFT JOIN vehicles v ON a.vehicle_id = v.id
     WHERE a.technician_id=? AND a.date>=? AND a.status='pending' ORDER BY a.date,a.time`,
    [req.session.customerId, today]
  ));
});
app.put('/api/tech/appointments/:id/complete', requireTech, async (req, res) => {
  const appt = await dbGet('SELECT * FROM appointments WHERE id=? AND technician_id=?', [+req.params.id, req.session.customerId]);
  if (!appt) return res.status(404).json({ error: 'Not found' });
  if (appt.status === 'completed') return res.status(409).json({ error: 'Ya completada' });
  const { tire_fl, tire_fr, tire_rl, tire_rr, brake_front, brake_rear, mileage } = req.body || {};
  await dbRun(`UPDATE appointments SET status='completed', mileage=?,
    tire_fl=?, tire_fr=?, tire_rl=?, tire_rr=?, brake_front=?, brake_rear=? WHERE id=?`,
    [mileage??null,tire_fl??null,tire_fr??null,tire_rl??null,tire_rr??null,brake_front??null,brake_rear??null,Number(appt.id)]);
  res.json({ success: true });
});

// ─── Password recovery ────────────────────────────────────────────────────────
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.redirect('/auth?tab=login&error=campos');
  const user = await dbGet("SELECT id, name, email FROM users WHERE email=? AND role='customer'", [email.trim().toLowerCase()]);
  if (!user) return res.redirect('/auth?tab=login&error=no_email');
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600_000).toISOString();
  await dbRun('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?', [token, expires, Number(user.id)]);
  const resetUrl = `${req.protocol}://${req.get('host')}/auth/reset-password?token=${token}`;
  const sent = await sendEmail(user.email, 'forgot_password', { name: user.name, resetLink: resetUrl });
  if (sent) return res.redirect('/auth?tab=login&reset=sent');
  res.redirect(`/auth?tab=login&reset=link&url=${encodeURIComponent(resetUrl)}`);
});
app.get('/auth/reset-password', (_req, res) => res.sendFile(path.join(__dirname, 'views', 'reset-password.html')));
app.post('/auth/reset-password', async (req, res) => {
  const { token, password, confirm } = req.body;
  if (!token || !password || !confirm) return res.redirect(`/auth/reset-password?token=${token||''}&error=campos`);
  if (password !== confirm) return res.redirect(`/auth/reset-password?token=${token}&error=match`);
  if (password.length < 6) return res.redirect(`/auth/reset-password?token=${token}&error=short`);
  const user = await dbGet('SELECT id, reset_expires FROM users WHERE reset_token=?', [token]);
  if (!user) return res.redirect(`/auth/reset-password?token=${token}&error=invalid`);
  if (new Date(user.reset_expires) < new Date()) return res.redirect(`/auth/reset-password?token=${token}&error=expired`);
  await dbRun('UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?', [hashPassword(password), Number(user.id)]);
  res.redirect('/auth?tab=login&reset=ok');
});

// ─── PayPal ───────────────────────────────────────────────────────────────────
const PAYPAL_SANDBOX = 'https://api-m.sandbox.paypal.com';
const PAYPAL_LIVE    = 'https://api-m.paypal.com';
const OIL_PRICES    = { 'Convencional': '65.00', 'Semi-sintético': '75.00', 'Sintético total': '85.00' };

async function getPayPalBase() {
  return (await getSetting('paypal_mode') || 'sandbox') === 'live' ? PAYPAL_LIVE : PAYPAL_SANDBOX;
}
async function getPayPalToken() {
  const clientId = await getSetting('paypal_client_id');
  const secret   = await getSetting('paypal_client_secret');
  if (!clientId || !secret) return null;
  const auth = Buffer.from(`${clientId}:${secret}`).toString('base64');
  try {
    const r = await fetch(`${await getPayPalBase()}/v1/oauth2/token`, {
      method: 'POST',
      headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials'
    });
    return (await r.json()).access_token || null;
  } catch { return null; }
}

app.get('/api/settings/paypal-client', async (_req, res) => {
  const clientId = await getSetting('paypal_client_id');
  res.json({ client_id: clientId || '', mode: await getSetting('paypal_mode') || 'sandbox', enabled: !!clientId });
});
app.post('/api/payments/create-order', requireCustomer, async (req, res) => {
  const { oil_type } = req.body;
  const price = OIL_PRICES[oil_type] || '65.00';
  const token = await getPayPalToken();
  if (!token) return res.status(503).json({ error: 'PayPal no configurado' });
  try {
    const r = await fetch(`${await getPayPalBase()}/v2/checkout/orders`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'PayPal-Request-Id': crypto.randomUUID() },
      body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ amount: { currency_code: 'USD', value: price }, description: `Cambio de aceite — ${oil_type}` }] })
    });
    const d = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: d.message || 'Error creando orden PayPal' });
    res.json({ order_id: d.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/payments/capture-order', requireCustomer, async (req, res) => {
  const { order_id, name, email, phone, vehicle, oil_type, date, time, notes, location, vehicle_id } = req.body;
  if (!order_id || !name || !phone || !vehicle || !date || !time || !location)
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  const u = await dbGet('SELECT email_verified FROM users WHERE id=?', [req.session.customerId]);
  if (u && !u.email_verified) return res.status(403).json({ error: 'verify_email' });
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate() + 1);
  if (date < tomorrow.toISOString().split('T')[0])
    return res.status(400).json({ error: 'Las citas deben agendarse con al menos 1 día de anticipación' });
  const exists = await dbGet("SELECT id FROM appointments WHERE date=? AND time=? AND status='pending'", [date, time]);
  if (exists) return res.status(409).json({ error: 'Ese horario ya está reservado' });
  const token = await getPayPalToken();
  if (!token) return res.status(503).json({ error: 'PayPal no configurado' });
  try {
    const captureRes = await fetch(`${await getPayPalBase()}/v2/checkout/orders/${order_id}/capture`, {
      method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    const captureData = await captureRes.json();
    if (!captureRes.ok || captureData.status !== 'COMPLETED')
      return res.status(400).json({ error: 'El pago no fue completado. Inténtalo de nuevo.' });
    const r = await dbRun(
      `INSERT INTO appointments (user_id,vehicle_id,name,email,phone,vehicle,oil_type,date,time,notes,location,is_recurring,recurrence_weeks)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [req.session.customerId, vehicle_id || null, name, email || '', phone, vehicle,
       oil_type || 'Convencional', date, time, notes || '', location, 0, 12]
    );
    const appt = await dbGet('SELECT a.*, v.color as vehicle_color FROM appointments a LEFT JOIN vehicles v ON a.vehicle_id=v.id WHERE a.id=?', [r.lastInsertRowid]);
    sendConfirmation(appt);
    res.json({ success: true, id: r.lastInsertRowid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/admin/settings/paypal', requireAdmin, async (_req, res) => {
  res.json({
    client_id: await getSetting('paypal_client_id') || '',
    client_secret_set: !!(await getSetting('paypal_client_secret')),
    mode: await getSetting('paypal_mode') || 'sandbox',
    configured: !!(await getSetting('paypal_client_id') && await getSetting('paypal_client_secret')),
  });
});
app.put('/api/admin/settings/paypal', requireAdmin, async (req, res) => {
  const { client_id, client_secret, mode } = req.body;
  if (!client_id?.trim()) return res.status(400).json({ error: 'Client ID es requerido' });
  await setSetting('paypal_client_id', client_id.trim());
  if (client_secret?.trim()) await setSetting('paypal_client_secret', client_secret.trim());
  await setSetting('paypal_mode', mode === 'live' ? 'live' : 'sandbox');
  res.json({ success: true });
});

// ─── Start ────────────────────────────────────────────────────────────────────
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Servidor:  http://localhost:${PORT}`);
    console.log(`📋 Admin:     http://localhost:${PORT}/admin`);
    console.log(`🔑 Login:     http://localhost:${PORT}/login\n`);
  });
}

module.exports = app;
