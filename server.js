// FleetFlow TMS - small-business transport management system
// Free stack: Node.js + Express + PostgreSQL + OpenStreetMap. No paid services.
const express = require('express');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const db = require('./db');

const app = express();
app.use(express.json({ limit: '6mb' }));

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;

// ---------- helpers ----------
const scrypt = (pw, salt) =>
  new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
const hashPw = async (pw) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = await scrypt(pw, salt);
  return salt + ':' + h.toString('hex');
};
const checkPw = async (pw, stored) => {
  const [salt, hex] = stored.split(':');
  const h = await scrypt(pw, salt);
  const a = Buffer.from(hex, 'hex');
  return a.length === h.length && crypto.timingSafeEqual(a, h);
};
const token = (n = 24) => crypto.randomBytes(n).toString('hex');
const cents = (v) => Math.round(Number(v || 0) * 100);
const num = (v, d = 0) => (v === undefined || v === null || v === '' ? d : Number(v));
const str = (v, d = '') => (v === undefined || v === null ? d : String(v).trim());

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

async function getUser(req) {
  const t = parseCookies(req).ff_session;
  if (!t) return null;
  const r = await db.q(
    `SELECT u.id, u.email, u.name, u.role FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > now()`,
    [t]
  );
  return r.rows[0] || null;
}

const auth = (fn) => async (req, res) => {
  try {
    const u = await getUser(req);
    if (!u) return res.status(401).json({ error: 'Not signed in' });
    req.user = u;
    await fn(req, res);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
};
const pub = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
};

async function getCompany() {
  const r = await db.q(`SELECT value FROM settings WHERE key = 'company'`);
  return r.rows[0] ? r.rows[0].value : {};
}
async function nextCode(prefix, table) {
  const yr = new Date().getFullYear();
  const r = await db.q(`SELECT count(*)::int AS n FROM ${table}`);
  return `${prefix}-${yr}-${String(r.rows[0].n + 1).padStart(4, '0')}`;
}
async function tripEvent(tripId, kind, note = '') {
  await db.q(`INSERT INTO trip_events (trip_id, kind, note) VALUES ($1,$2,$3)`, [tripId, kind, note]);
}

// ---------- SPA ----------
app.get(['/', '/drive/:token'], (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// ---------- auth ----------
app.get('/api/bootstrap', pub(async (req, res) => {
  const r = await db.q('SELECT count(*)::int AS n FROM users');
  const c = await getCompany();
  res.json({ needsSetup: r.rows[0].n === 0, company: c.name || 'FleetFlow', user: await getUser(req) });
}));

app.post('/api/setup', pub(async (req, res) => {
  const has = await db.q('SELECT count(*)::int AS n FROM users');
  if (has.rows[0].n > 0) return res.status(400).json({ error: 'Setup already done' });
  const { company, name, email, password, currency } = req.body || {};
  if (!name || !email || !password || String(password).length < 6)
    return res.status(400).json({ error: 'Name, email and a password of 6+ characters are required' });
  const h = await hashPw(String(password));
  const r = await db.q(
    'INSERT INTO users (email, name, pass_hash, role) VALUES ($1,$2,$3,$4) RETURNING id',
    [str(email).toLowerCase(), str(name), h, 'owner']
  );
  await db.q(
    `INSERT INTO settings (key, value) VALUES ('company', $1)
     ON CONFLICT (key) DO UPDATE SET value = settings.value || $1::jsonb`,
    [JSON.stringify({ name: str(company) || str(name) + ' Transport', currency: str(currency) || 'EUR' })]
  );
  const t = token();
  await db.q('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2, now() + $3::interval)', [t, r.rows[0].id, SESSION_DAYS + ' days']);
  res.setHeader('Set-Cookie', `ff_session=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}; Secure`);
  res.json({ ok: true });
}));

app.post('/api/login', pub(async (req, res) => {
  const { email, password } = req.body || {};
  const r = await db.q('SELECT * FROM users WHERE email = $1', [str(email).toLowerCase()]);
  if (!r.rows[0] || !(await checkPw(String(password || ''), r.rows[0].pass_hash)))
    return res.status(401).json({ error: 'Wrong email or password' });
  const t = token();
  await db.q('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2, now() + $3::interval)', [t, r.rows[0].id, SESSION_DAYS + ' days']);
  res.setHeader('Set-Cookie', `ff_session=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}; Secure`);
  res.json({ ok: true, name: r.rows[0].name });
}));

app.post('/api/logout', pub(async (req, res) => {
  const t = parseCookies(req).ff_session;
  if (t) await db.q('DELETE FROM sessions WHERE token = $1', [t]);
  res.setHeader('Set-Cookie', 'ff_session=; Path=/; HttpOnly; Max-Age=0');
  res.json({ ok: true });
}));

// ---------- settings ----------
app.get('/api/settings', auth(async (req, res) => res.json(await getCompany())));
app.put('/api/settings', auth(async (req, res) => {
  const cur = await getCompany();
  const b = req.body || {};
  const next = {
    name: str(b.name, cur.name), address: str(b.address, cur.address), vat: str(b.vat, cur.vat),
    phone: str(b.phone, cur.phone), email: str(b.email, cur.email), currency: str(b.currency, cur.currency || 'EUR'),
  };
  await db.q(`UPDATE settings SET value = $1 WHERE key = 'company'`, [JSON.stringify(next)]);
  res.json(next);
}));

// ---------- generic CRUD factory ----------
function crud(path, table, fields, orderBy = 'id DESC') {
  app.get(`/api/${path}`, auth(async (req, res) => {
    const r = await db.q(`SELECT * FROM ${table} ORDER BY ${orderBy} LIMIT 500`);
    res.json(r.rows);
  }));
  app.post(`/api/${path}`, auth(async (req, res) => {
    const cols = fields.filter((f) => req.body[f] !== undefined);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to save' });
    const vals = cols.map((c) => req.body[c]);
    const r = await db.q(
      `INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map((_, i) => '$' + (i + 1)).join(',')}) RETURNING *`,
      vals
    );
    res.json(r.rows[0]);
  }));
  app.put(`/api/${path}/:id`, auth(async (req, res) => {
    const cols = fields.filter((f) => req.body[f] !== undefined);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to update' });
    const vals = cols.map((c) => req.body[c]);
    vals.push(req.params.id);
    const r = await db.q(
      `UPDATE ${table} SET ${cols.map((c, i) => `${c} = $${i + 1}`).join(', ')} WHERE id = $${cols.length + 1} RETURNING *`,
      vals
    );
    res.json(r.rows[0] || {});
  }));
  app.delete(`/api/${path}/:id`, auth(async (req, res) => {
    await db.q(`DELETE FROM ${table} WHERE id = $1`, [req.params.id]);
    res.json({ ok: true });
  }));
}

crud('customers', 'customers', ['name', 'phone', 'email', 'address', 'notes']);
crud('trucks', 'trucks', ['plate', 'label', 'type', 'capacity_kg', 'status']);
crud('drivers', 'drivers', ['name', 'phone', 'license_no', 'status']);

// ---------- orders ----------
app.get('/api/orders', auth(async (req, res) => {
  const r = await db.q(
    `SELECT o.*, c.name AS customer_name,
       (SELECT t.id FROM trips t JOIN trip_orders x ON x.trip_id = t.id
        WHERE x.order_id = o.id AND t.status NOT IN ('completed','cancelled') LIMIT 1) AS active_trip_id
     FROM orders o LEFT JOIN customers c ON c.id = o.customer_id
     ORDER BY o.id DESC LIMIT 500`
  );
  res.json(r.rows);
}));

app.post('/api/orders', auth(async (req, res) => {
  const b = req.body || {};
  if (!str(b.pickup_addr) || !str(b.delivery_addr)) return res.status(400).json({ error: 'Pickup and delivery addresses are required' });
  const code = await nextCode('ORD', 'orders');
  const r = await db.q(
    `INSERT INTO orders (code, customer_id, pickup_addr, pickup_lat, pickup_lon, delivery_addr, delivery_lat, delivery_lon,
       goods, weight_kg, pallets, price_cents, status, pickup_date, delivery_date, notes, is_demo)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'new',$13,$14,$15,false) RETURNING *`,
    [code, b.customer_id || null, str(b.pickup_addr), b.pickup_lat || null, b.pickup_lon || null,
     str(b.delivery_addr), b.delivery_lat || null, b.delivery_lon || null, str(b.goods), num(b.weight_kg),
     num(b.pallets), cents(b.price), b.pickup_date || null, b.delivery_date || null, str(b.notes)]
  );
  res.json(r.rows[0]);
}));

app.put('/api/orders/:id', auth(async (req, res) => {
  const b = req.body || {};
  const r = await db.q(
    `UPDATE orders SET customer_id=$2, pickup_addr=$3, pickup_lat=$4, pickup_lon=$5, delivery_addr=$6, delivery_lat=$7, delivery_lon=$8,
       goods=$9, weight_kg=$10, pallets=$11, price_cents=$12, status=$13, pickup_date=$14, delivery_date=$15, notes=$16
     WHERE id=$1 RETURNING *`,
    [req.params.id, b.customer_id || null, str(b.pickup_addr), b.pickup_lat || null, b.pickup_lon || null,
     str(b.delivery_addr), b.delivery_lat || null, b.delivery_lon || null, str(b.goods), num(b.weight_kg),
     num(b.pallets), cents(b.price), str(b.status, 'new'), b.pickup_date || null, b.delivery_date || null, str(b.notes)]
  );
  res.json(r.rows[0] || {});
}));

app.delete('/api/orders/:id', auth(async (req, res) => {
  await db.q('DELETE FROM orders WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

// ---------- trips ----------
app.get('/api/trips', auth(async (req, res) => {
  const r = await db.q(
    `SELECT t.*, tr.plate AS truck_plate, d.name AS driver_name,
       (SELECT count(*)::int FROM trip_orders x WHERE x.trip_id = t.id) AS order_count,
       (SELECT COALESCE(sum(amount_cents),0)::int FROM costs c WHERE c.trip_id = t.id) AS cost_cents,
       (SELECT COALESCE(sum(o.price_cents),0)::int FROM trip_orders x JOIN orders o ON o.id = x.order_id WHERE x.trip_id = t.id) AS revenue_cents,
       (SELECT json_build_object('lat', l.lat, 'lon', l.lon, 'ts', l.ts) FROM locations l
        WHERE l.trip_id = t.id ORDER BY l.ts DESC LIMIT 1) AS last_loc
     FROM trips t LEFT JOIN trucks tr ON tr.id = t.truck_id LEFT JOIN drivers d ON d.id = t.driver_id
     ORDER BY t.id DESC LIMIT 300`
  );
  res.json(r.rows);
}));

app.post('/api/trips', auth(async (req, res) => {
  const b = req.body || {};
  const code = await nextCode('TRP', 'trips');
  const r = await db.q(
    `INSERT INTO trips (code, truck_id, driver_id, status, planned_start, notes, share_token)
     VALUES ($1,$2,$3,'planned',$4,$5,$6) RETURNING *`,
    [code, b.truck_id || null, b.driver_id || null, b.planned_start || null, str(b.notes), token(16)]
  );
  await tripEvent(r.rows[0].id, 'created', 'Trip planned');
  if (b.truck_id) await db.q(`UPDATE trucks SET status = 'on_trip' WHERE id = $1 AND status = 'active'`, [b.truck_id]);
  res.json(r.rows[0]);
}));

app.get('/api/trips/:id', auth(async (req, res) => {
  const t = await db.q(
    `SELECT t.*, tr.plate AS truck_plate, tr.label AS truck_label, d.name AS driver_name, d.phone AS driver_phone
     FROM trips t LEFT JOIN trucks tr ON tr.id = t.truck_id LEFT JOIN drivers d ON d.id = t.driver_id WHERE t.id = $1`,
    [req.params.id]
  );
  if (!t.rows[0]) return res.status(404).json({ error: 'Trip not found' });
  const orders = await db.q(
    `SELECT o.*, c.name AS customer_name, x.seq FROM trip_orders x JOIN orders o ON o.id = x.order_id
     LEFT JOIN customers c ON c.id = o.customer_id WHERE x.trip_id = $1 ORDER BY x.seq`,
    [req.params.id]
  );
  const events = await db.q('SELECT * FROM trip_events WHERE trip_id = $1 ORDER BY ts DESC LIMIT 100', [req.params.id]);
  const costs = await db.q('SELECT * FROM costs WHERE trip_id = $1 ORDER BY ts DESC', [req.params.id]);
  const pod = await db.q('SELECT id, receiver_name, note, lat, lon, signed_at, (signature_png IS NOT NULL) AS has_signature FROM pods WHERE trip_id = $1', [req.params.id]);
  res.json({ trip: t.rows[0], orders: orders.rows, events: events.rows, costs: costs.rows, pod: pod.rows[0] || null });
}));

app.put('/api/trips/:id', auth(async (req, res) => {
  const b = req.body || {};
  const r = await db.q(
    `UPDATE trips SET truck_id=$2, driver_id=$3, planned_start=$4, notes=$5 WHERE id=$1 RETURNING *`,
    [req.params.id, b.truck_id || null, b.driver_id || null, b.planned_start || null, str(b.notes)]
  );
  res.json(r.rows[0] || {});
}));

app.delete('/api/trips/:id', auth(async (req, res) => {
  await db.q('DELETE FROM trips WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

app.post('/api/trips/:id/orders', auth(async (req, res) => {
  const { order_id } = req.body || {};
  const seq = await db.q('SELECT COALESCE(max(seq),0)+1 AS s FROM trip_orders WHERE trip_id = $1', [req.params.id]);
  await db.q('INSERT INTO trip_orders (trip_id, order_id, seq) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [req.params.id, order_id, seq.rows[0].s]);
  await db.q(`UPDATE orders SET status = 'planned' WHERE id = $1 AND status = 'new'`, [order_id]);
  await tripEvent(req.params.id, 'order_added', 'Order #' + order_id + ' added');
  res.json({ ok: true });
}));

app.delete('/api/trips/:id/orders/:oid', auth(async (req, res) => {
  await db.q('DELETE FROM trip_orders WHERE trip_id = $1 AND order_id = $2', [req.params.id, req.params.oid]);
  await db.q(`UPDATE orders SET status = 'new' WHERE id = $1 AND status = 'planned'`, [req.params.oid]);
  res.json({ ok: true });
}));

const TRIP_FLOW = ['planned', 'loading', 'in_transit', 'completed', 'cancelled'];
async function setTripStatus(id, status, note) {
  const cur = await db.q('SELECT * FROM trips WHERE id = $1', [id]);
  if (!cur.rows[0]) return null;
  const t = cur.rows[0];
  const sets = ['status = $2'];
  if (status === 'in_transit' && !t.started_at) sets.push('started_at = now()');
  if (status === 'completed') sets.push('completed_at = now()');
  await db.q(`UPDATE trips SET ${sets.join(', ')} WHERE id = $1`, [id, status]);
  if (status === 'in_transit') {
    await db.q(`UPDATE orders SET status = 'in_transit' WHERE id IN (SELECT order_id FROM trip_orders WHERE trip_id = $1)`, [id]);
  }
  if (status === 'completed') {
    await db.q(`UPDATE orders SET status = 'delivered' WHERE id IN (SELECT order_id FROM trip_orders WHERE trip_id = $1)`, [id]);
    if (t.truck_id) await db.q(`UPDATE trucks SET status = 'active' WHERE id = $1`, [t.truck_id]);
  }
  if (status === 'cancelled' && t.truck_id) await db.q(`UPDATE trucks SET status = 'active' WHERE id = $1`, [t.truck_id]);
  await tripEvent(id, 'status', (note ? note + ' - ' : '') + 'Status: ' + status.replace('_', ' '));
  return true;
}

app.post('/api/trips/:id/status', auth(async (req, res) => {
  const s = str((req.body || {}).status);
  if (!TRIP_FLOW.includes(s)) return res.status(400).json({ error: 'Bad status' });
  if (!(await setTripStatus(req.params.id, s, str((req.body || {}).note)))) return res.status(404).json({ error: 'Trip not found' });
  res.json({ ok: true });
}));

app.post('/api/trips/:id/costs', auth(async (req, res) => {
  const b = req.body || {};
  const r = await db.q('INSERT INTO costs (trip_id, kind, amount_cents, note) VALUES ($1,$2,$3,$4) RETURNING *',
    [req.params.id, ['fuel', 'toll', 'other'].includes(b.kind) ? b.kind : 'other', cents(b.amount), str(b.note)]);
  res.json(r.rows[0]);
}));
app.delete('/api/costs/:id', auth(async (req, res) => {
  await db.q('DELETE FROM costs WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

app.post('/api/trips/:id/share/regenerate', auth(async (req, res) => {
  const r = await db.q('UPDATE trips SET share_token = $2 WHERE id = $1 RETURNING share_token', [req.params.id, token(16)]);
  res.json(r.rows[0] || {});
}));

app.get('/api/trips/:id/locations', auth(async (req, res) => {
  const r = await db.q('SELECT lat, lon, speed, ts FROM locations WHERE trip_id = $1 ORDER BY ts ASC LIMIT 2000', [req.params.id]);
  res.json(r.rows);
}));

// ---------- driver mode (public, token) ----------
async function tripByToken(tkn) {
  const r = await db.q(
    `SELECT t.id, t.code, t.status, t.planned_start, t.share_token, tr.plate AS truck_plate, d.name AS driver_name
     FROM trips t LEFT JOIN trucks tr ON tr.id = t.truck_id LEFT JOIN drivers d ON d.id = t.driver_id
     WHERE t.share_token = $1`,
    [tkn]
  );
  return r.rows[0] || null;
}

app.get('/api/drive/:token', pub(async (req, res) => {
  const t = await tripByToken(req.params.token);
  if (!t) return res.status(404).json({ error: 'Link not valid' });
  const orders = await db.q(
    `SELECT o.code, o.pickup_addr, o.delivery_addr, o.goods, o.status, x.seq, c.name AS customer_name
     FROM trip_orders x JOIN orders o ON o.id = x.order_id LEFT JOIN customers c ON c.id = o.customer_id
     WHERE x.trip_id = $1 ORDER BY x.seq`,
    [t.id]
  );
  const pod = await db.q('SELECT signed_at, receiver_name FROM pods WHERE trip_id = $1', [t.id]);
  res.json({ trip: t, orders: orders.rows, pod: pod.rows[0] || null });
}));

app.post('/api/drive/:token/location', pub(async (req, res) => {
  const t = await tripByToken(req.params.token);
  if (!t) return res.status(404).json({ error: 'Link not valid' });
  const b = req.body || {};
  const lat = Number(b.lat), lon = Number(b.lon);
  if (!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180)
    return res.status(400).json({ error: 'Bad coordinates' });
  await db.q('INSERT INTO locations (trip_id, lat, lon, speed, heading, accuracy) VALUES ($1,$2,$3,$4,$5,$6)',
    [t.id, lat, lon, num(b.speed, null), num(b.heading, null), num(b.accuracy, null)]);
  // prune old pings: keep 3 days
  await db.q(`DELETE FROM locations WHERE trip_id = $1 AND ts < now() - interval '3 days'`, [t.id]);
  res.json({ ok: true });
}));

app.post('/api/drive/:token/status', pub(async (req, res) => {
  const t = await tripByToken(req.params.token);
  if (!t) return res.status(404).json({ error: 'Link not valid' });
  const s = str((req.body || {}).status);
  if (!['loading', 'in_transit', 'completed'].includes(s)) return res.status(400).json({ error: 'Bad status' });
  await setTripStatus(t.id, s, 'Driver');
  res.json({ ok: true });
}));

app.post('/api/drive/:token/pod', pub(async (req, res) => {
  const t = await tripByToken(req.params.token);
  if (!t) return res.status(404).json({ error: 'Link not valid' });
  const b = req.body || {};
  if (!str(b.receiver_name)) return res.status(400).json({ error: 'Receiver name is required' });
  let sig = null;
  if (str(b.signature) && str(b.signature).startsWith('data:image/png;base64,')) {
    sig = Buffer.from(str(b.signature).slice('data:image/png;base64,'.length), 'base64');
    if (sig.length > 2_000_000) sig = null;
  }
  await db.q(
    `INSERT INTO pods (trip_id, receiver_name, note, signature_png, lat, lon)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (trip_id) DO UPDATE SET receiver_name=$2, note=$3, signature_png=$4, lat=$5, lon=$6, signed_at=now()`,
    [t.id, str(b.receiver_name), str(b.note), sig, isFinite(Number(b.lat)) ? Number(b.lat) : null, isFinite(Number(b.lon)) ? Number(b.lon) : null]
  );
  await tripEvent(t.id, 'pod', 'POD signed by ' + str(b.receiver_name));
  await setTripStatus(t.id, 'completed', 'POD received');
  res.json({ ok: true });
}));

// ---------- documents (DDT / POD PDF) ----------
function money(c, cur) {
  return new Intl.NumberFormat('en', { style: 'currency', currency: cur || 'EUR' }).format((c || 0) / 100);
}
async function tripFull(id) {
  const t = await db.q(
    `SELECT t.*, tr.plate AS truck_plate, tr.label AS truck_label, d.name AS driver_name, d.license_no
     FROM trips t LEFT JOIN trucks tr ON tr.id = t.truck_id LEFT JOIN drivers d ON d.id = t.driver_id WHERE t.id = $1`, [id]);
  const orders = await db.q(
    `SELECT o.*, c.name AS customer_name, c.address AS customer_addr, x.seq FROM trip_orders x
     JOIN orders o ON o.id = x.order_id LEFT JOIN customers c ON c.id = o.customer_id WHERE x.trip_id = $1 ORDER BY x.seq`, [id]);
  return { trip: t.rows[0], orders: orders.rows };
}
function pdfRes(res, name) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${name}"`);
  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  doc.pipe(res);
  return doc;
}

app.get('/api/trips/:id/ddt.pdf', auth(async (req, res) => {
  const { trip, orders } = await tripFull(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });
  const co = await getCompany();
  const doc = pdfRes(res, `DDT-${trip.code}.pdf`);
  doc.fontSize(20).fillColor('#0f2a43').text(co.name || 'Transport Company', { continued: false });
  doc.fontSize(9).fillColor('#444');
  [co.address, co.vat && 'VAT: ' + co.vat, co.phone, co.email].filter(Boolean).forEach((l) => doc.text(l));
  doc.moveUp(4);
  doc.fontSize(16).fillColor('#b45309').text('DDT - Documento di Trasporto', 320, 50, { align: 'right' });
  doc.fontSize(10).fillColor('#333').text(`N. ${trip.code}`, { align: 'right' });
  doc.text(`Data: ${new Date().toLocaleDateString('en-GB')}`, { align: 'right' });
  doc.moveDown(2);
  const y0 = doc.y;
  doc.fontSize(11).fillColor('#0f2a43').text('Mittente / Sender', 50, y0);
  doc.fontSize(9).fillColor('#333').text([co.name, co.address].filter(Boolean).join('\n'), 50, y0 + 14);
  doc.fontSize(11).fillColor('#0f2a43').text('Destinatario / Consignee', 320, y0);
  const first = orders[0];
  doc.fontSize(9).fillColor('#333').text(first ? [first.customer_name || '', first.delivery_addr].filter(Boolean).join('\n') : '-', 320, y0 + 14);
  doc.moveDown(4);
  doc.fontSize(11).fillColor('#0f2a43').text('Vettore / Carrier');
  doc.fontSize(9).fillColor('#333').text(`Driver: ${trip.driver_name || '-'}   Truck: ${trip.truck_plate || '-'}${trip.license_no ? '   License: ' + trip.license_no : ''}`);
  doc.moveDown();
  doc.fontSize(11).fillColor('#0f2a43').text('Beni trasportati / Goods');
  doc.moveDown(0.3);
  let totW = 0, totP = 0;
  orders.forEach((o, i) => {
    totW += Number(o.weight_kg || 0); totP += Number(o.pallets || 0);
    doc.fontSize(9).fillColor('#333')
      .text(`${i + 1}. ${o.code} - ${o.goods || 'General goods'}`, { continued: false })
      .text(`   From: ${o.pickup_addr}  ->  To: ${o.delivery_addr}`)
      .text(`   Weight: ${o.weight_kg || 0} kg   Pallets: ${o.pallets || 0}`);
    doc.moveDown(0.4);
  });
  doc.moveDown(0.5);
  doc.fontSize(10).text(`Totals: ${totW} kg, ${totP} pallets, ${orders.length} shipment(s)`);
  doc.moveDown(2);
  doc.fontSize(9).text('Causale / Reason: Vendita / Sale - transport for delivery of goods.');
  doc.moveDown(3);
  const y = doc.y;
  doc.text('_____________________', 50, y).text('_____________________', 220, y).text('_____________________', 400, y);
  doc.text('Firma Mittente', 50, y + 12).text('Firma Vettore', 220, y + 12).text('Firma Destinatario', 400, y + 12);
  doc.fontSize(7).fillColor('#888').text('Generated by FleetFlow TMS - ' + new Date().toISOString(), 50, 800);
  doc.end();
}));

app.get('/api/trips/:id/pod.pdf', auth(async (req, res) => {
  const { trip, orders } = await tripFull(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });
  const pod = await db.q('SELECT * FROM pods WHERE trip_id = $1', [trip.id]);
  const co = await getCompany();
  const doc = pdfRes(res, `POD-${trip.code}.pdf`);
  doc.fontSize(18).fillColor('#0f2a43').text('Proof of Delivery (POD)');
  doc.moveDown(0.5);
  doc.fontSize(10).fillColor('#333')
    .text(`Trip: ${trip.code}    Date: ${new Date().toLocaleDateString('en-GB')}`)
    .text(`Carrier: ${co.name || ''}`)
    .text(`Driver: ${trip.driver_name || '-'}   Truck: ${trip.truck_plate || '-'}`);
  doc.moveDown();
  doc.fontSize(11).fillColor('#0f2a43').text('Delivered shipments');
  orders.forEach((o, i) => {
    doc.fontSize(9).fillColor('#333').text(`${i + 1}. ${o.code} -> ${o.delivery_addr} (${o.goods || 'goods'}, ${o.weight_kg || 0} kg)`);
  });
  doc.moveDown(1.5);
  if (pod.rows[0]) {
    const p = pod.rows[0];
    doc.fontSize(11).fillColor('#0f2a43').text('Delivery confirmation');
    doc.fontSize(10).fillColor('#333')
      .text(`Received by: ${p.receiver_name}`)
      .text(`Signed at: ${new Date(p.signed_at).toLocaleString('en-GB')}`)
      .text(p.lat ? `Location: ${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}` : 'Location: not recorded');
    if (p.note) doc.text(`Note: ${p.note}`);
    if (p.signature_png) {
      doc.moveDown(0.5);
      doc.image(p.signature_png, { width: 220 });
      doc.fontSize(8).fillColor('#666').text('Receiver signature (captured on driver device)');
    }
  } else {
    doc.fontSize(10).fillColor('#8a6d1a').text('Delivery not yet confirmed. The receiver can sign on the driver device; this document updates automatically.');
    doc.moveDown(2);
    doc.text('_____________________').text('Receiver name and signature');
  }
  doc.fontSize(7).fillColor('#888').text('Generated by FleetFlow TMS - ' + new Date().toISOString(), 50, 800);
  doc.end();
}));

// ---------- geocoding (OpenStreetMap Nominatim, cached) ----------
app.post('/api/geocode', auth(async (req, res) => {
  const qtext = str((req.body || {}).q);
  if (!qtext) return res.status(400).json({ error: 'Missing query' });
  const key = qtext.toLowerCase();
  const cached = await db.q('SELECT lat, lon, label FROM geocode_cache WHERE query = $1', [key]);
  if (cached.rows[0]) return res.json(cached.rows[0]);
  const url = 'https://nominatim.openstreetmap.org/search?format=json&limit=1&q=' + encodeURIComponent(qtext);
  const r = await fetch(url, { headers: { 'User-Agent': 'FleetFlow-TMS/1.0 (small-business TMS, contact: owner)' } });
  const js = await r.json();
  if (!js || !js[0]) return res.status(404).json({ error: 'Address not found' });
  const lat = parseFloat(js[0].lat), lon = parseFloat(js[0].lon);
  await db.q('INSERT INTO geocode_cache (query, lat, lon, label) VALUES ($1,$2,$3,$4) ON CONFLICT (query) DO NOTHING',
    [key, lat, lon, js[0].display_name || qtext]);
  res.json({ lat, lon, label: js[0].display_name || qtext });
}));

// ---------- dashboard & reports ----------
app.get('/api/dashboard', auth(async (req, res) => {
  const [kpi, recent, activeTrips, monthly] = await Promise.all([
    db.q(`SELECT
      (SELECT count(*)::int FROM orders WHERE status NOT IN ('delivered','invoiced','cancelled')) AS open_orders,
      (SELECT count(*)::int FROM trips WHERE status IN ('planned','loading','in_transit')) AS active_trips,
      (SELECT count(*)::int FROM trucks WHERE status = 'active') AS trucks_free,
      (SELECT count(*)::int FROM trucks) AS trucks_total,
      (SELECT COALESCE(sum(price_cents),0)::int FROM orders WHERE status IN ('delivered','invoiced')
        AND created_at > date_trunc('month', now())) AS month_revenue,
      (SELECT COALESCE(sum(amount_cents),0)::int FROM costs
        WHERE ts > date_trunc('month', now())) AS month_costs`),
    db.q(`SELECT e.ts, e.kind, e.note, t.code FROM trip_events e JOIN trips t ON t.id = e.trip_id ORDER BY e.ts DESC LIMIT 12`),
    db.q(`SELECT t.id, t.code, t.status, tr.plate, d.name AS driver_name,
        (SELECT json_build_object('lat', l.lat, 'lon', l.lon, 'ts', l.ts) FROM locations l WHERE l.trip_id = t.id ORDER BY l.ts DESC LIMIT 1) AS last_loc
      FROM trips t LEFT JOIN trucks tr ON tr.id = t.truck_id LEFT JOIN drivers d ON d.id = t.driver_id
      WHERE t.status IN ('loading','in_transit') LIMIT 20`),
    db.q(`SELECT to_char(m, 'YYYY-MM') AS month,
        COALESCE((SELECT sum(o.price_cents) FROM orders o WHERE o.status IN ('delivered','invoiced') AND date_trunc('month', o.created_at) = m),0)::int AS revenue,
        COALESCE((SELECT sum(c.amount_cents) FROM costs c WHERE date_trunc('month', c.ts) = m),0)::int AS costs
      FROM generate_series(date_trunc('month', now()) - interval '5 months', date_trunc('month', now()), interval '1 month') m`),
  ]);
  const co = await getCompany();
  res.json({ kpi: kpi.rows[0], recent: recent.rows, active: activeTrips.rows, monthly: monthly.rows, currency: co.currency || 'EUR' });
}));

app.get('/api/reports/summary', auth(async (req, res) => {
  const perTruck = await db.q(
    `SELECT tr.plate, count(DISTINCT t.id)::int AS trips,
       COALESCE(sum(c.amount_cents),0)::int AS cost_cents,
       COALESCE((SELECT sum(o.price_cents) FROM trip_orders x JOIN orders o ON o.id = x.order_id WHERE x.trip_id IN (SELECT id FROM trips t2 WHERE t2.truck_id = tr.id AND t2.status = 'completed')),0)::int AS revenue_cents
     FROM trucks tr LEFT JOIN trips t ON t.truck_id = tr.id AND t.status = 'completed' LEFT JOIN costs c ON c.trip_id = t.id
     GROUP BY tr.id, tr.plate ORDER BY cost_cents DESC`);
  const perDriver = await db.q(
    `SELECT d.name, count(t.id)::int AS trips, COALESCE(sum(c.amount_cents),0)::int AS cost_cents
     FROM drivers d LEFT JOIN trips t ON t.driver_id = d.id AND t.status = 'completed' LEFT JOIN costs c ON c.trip_id = t.id
     GROUP BY d.id, d.name ORDER BY trips DESC`);
  const perKind = await db.q(`SELECT kind, sum(amount_cents)::int AS total FROM costs GROUP BY kind ORDER BY total DESC`);
  const topCustomers = await db.q(
    `SELECT c.name, count(o.id)::int AS orders, sum(o.price_cents)::int AS revenue_cents
     FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.status IN ('delivered','invoiced')
     GROUP BY c.name ORDER BY revenue_cents DESC LIMIT 10`);
  res.json({ perTruck: perTruck.rows, perDriver: perDriver.rows, perKind: perKind.rows, topCustomers: topCustomers.rows });
}));

app.get('/api/reports/costs.csv', auth(async (req, res) => {
  const r = await db.q(
    `SELECT t.code AS trip, c.kind, c.amount_cents, c.note, c.ts, tr.plate AS truck
     FROM costs c JOIN trips t ON t.id = c.trip_id LEFT JOIN trucks tr ON tr.id = t.truck_id ORDER BY c.ts DESC`);
  const co = await getCompany();
  const rows = [['trip', 'truck', 'kind', 'amount_' + (co.currency || 'EUR'), 'note', 'date']];
  r.rows.forEach((x) => rows.push([x.trip, x.truck || '', x.kind, (x.amount_cents / 100).toFixed(2), (x.note || '').replace(/[\r\n,]+/g, ' '), new Date(x.ts).toISOString().slice(0, 10)]));
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="fleetflow-costs.csv"');
  res.send(rows.map((r2) => r2.map((c) => (/[",\n]/.test(String(c)) ? '"' + String(c).replace(/"/g, '""') + '"' : c)).join(',')).join('\n'));
}));

// ---------- demo data ----------
app.post('/api/demo/seed', auth(async (req, res) => {
  const has = await db.q('SELECT count(*)::int AS n FROM customers WHERE is_demo');
  if (has.rows[0].n > 0) return res.json({ ok: true, already: true });
  await db.q('BEGIN');
  try {
  const c = await db.q(
    `INSERT INTO customers (name, phone, email, address, is_demo) VALUES
     ('DEMO - Rossi Alimentari SRL', '+39 02 555 0101', 'orders@rossi-alim.example', 'Via delle Industrie 12, Milan, Italy', true),
     ('DEMO - Tanaka Fresh Market', '+60 3 555 0142', 'buy@tanakafresh.example', 'Jalan SS2/24, Petaling Jaya, Malaysia', true),
     ('DEMO - Dhaka Textile Hub', '+880 2 555 0177', 'logistics@dhakatex.example', 'Tejgaon I/A, Dhaka, Bangladesh', true) RETURNING id`
  );
  await db.q(
    `INSERT INTO trucks (plate, label, type, capacity_kg, is_demo) VALUES
     ('DEMO-101', 'Iveco Daily 35S', 'van', 1500, true),
     ('DEMO-202', 'Volvo FH16', 'truck', 18000, true),
     ('DEMO-303', 'Isuzu N-Series', 'box', 3500, true)`
  );
  await db.q(
    `INSERT INTO drivers (name, phone, license_no, is_demo) VALUES
     ('DEMO - Marco Bianchi', '+39 333 555 0101', 'IT-MB-77123', true),
     ('DEMO - Amir Hamzah', '+60 12 555 0143', 'MY-AH-55401', true)`
  );
  const demoOrders = [
    [c.rows[0].id, 'Via Tortona 31, Milan, Italy', 45.4520, 9.1570, 'Corso Buenos Aires 15, Milan, Italy', 45.4740, 9.2100, 'Packed food products', 850, 4, 42000, 'Handle with care'],
    [c.rows[1].id, 'Pelabuhan Klang, Selangor, Malaysia', 3.0048, 101.3920, 'Jalan Bukit Bintang, Kuala Lumpur, Malaysia', 3.1466, 101.7109, 'Frozen seafood', 2200, 8, 95000, 'Refrigerated'],
    [c.rows[2].id, 'Tejgaon I/A, Dhaka, Bangladesh', 23.7644, 90.3950, 'Zirabo, Ashulia, Dhaka, Bangladesh', 23.9010, 90.3270, 'Textile rolls', 1400, 6, 38000, ''],
  ];
  let day = 1;
  for (const o of demoOrders) {
    await db.q(
      `INSERT INTO orders (code, customer_id, pickup_addr, pickup_lat, pickup_lon, delivery_addr, delivery_lat, delivery_lon, goods, weight_kg, pallets, price_cents, status, pickup_date, delivery_date, notes, is_demo)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'new', CURRENT_DATE + ($13)::int, CURRENT_DATE + ($13)::int, $14, true)`,
      [await nextCode('ORD', 'orders'), o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], day++, o[11]]
    );
  }
  await db.q('COMMIT');
  } catch (e) {
    await db.q('ROLLBACK');
    throw e;
  }
  res.json({ ok: true });
}));

app.post('/api/demo/clear', auth(async (req, res) => {
  await db.q(`DELETE FROM trips WHERE is_demo`);
  await db.q(`DELETE FROM orders WHERE is_demo`);
  await db.q(`DELETE FROM trucks WHERE is_demo`);
  await db.q(`DELETE FROM drivers WHERE is_demo`);
  await db.q(`DELETE FROM customers WHERE is_demo`);
  res.json({ ok: true });
}));

// ---------- start ----------
db.init()
  .then(() => {
    app.listen(PORT, () => console.log('FleetFlow TMS listening on :' + PORT));
  })
  .catch((e) => {
    console.error('DB init failed:', e);
    process.exit(1);
  });
