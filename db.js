// FleetFlow TMS - database layer (PostgreSQL / Neon)
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('neon.tech')
    ? { rejectUnauthorized: false }
    : (process.env.PGSSL === '1' ? { rejectUnauthorized: false } : false),
  max: 5,
});

async function q(text, params) {
  return pool.query(text, params);
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  address TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  is_demo BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS trucks (
  id SERIAL PRIMARY KEY,
  plate TEXT UNIQUE NOT NULL,
  label TEXT DEFAULT '',
  type TEXT DEFAULT 'box',
  capacity_kg INT DEFAULT 3500,
  status TEXT NOT NULL DEFAULT 'active',
  is_demo BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS drivers (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  license_no TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  is_demo BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  customer_id INT REFERENCES customers(id) ON DELETE SET NULL,
  pickup_addr TEXT NOT NULL,
  pickup_lat DOUBLE PRECISION,
  pickup_lon DOUBLE PRECISION,
  delivery_addr TEXT NOT NULL,
  delivery_lat DOUBLE PRECISION,
  delivery_lon DOUBLE PRECISION,
  goods TEXT DEFAULT '',
  weight_kg NUMERIC DEFAULT 0,
  pallets INT DEFAULT 0,
  price_cents INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new',
  pickup_date DATE,
  delivery_date DATE,
  notes TEXT DEFAULT '',
  is_demo BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS trips (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  truck_id INT REFERENCES trucks(id) ON DELETE SET NULL,
  driver_id INT REFERENCES drivers(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  planned_start TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  notes TEXT DEFAULT '',
  share_token TEXT UNIQUE,
  is_demo BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS trip_orders (
  trip_id INT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  seq INT NOT NULL DEFAULT 1,
  PRIMARY KEY (trip_id, order_id)
);
CREATE TABLE IF NOT EXISTS trip_events (
  id BIGSERIAL PRIMARY KEY,
  trip_id INT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind TEXT NOT NULL,
  note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS locations (
  id BIGSERIAL PRIMARY KEY,
  trip_id INT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  lat DOUBLE PRECISION NOT NULL,
  lon DOUBLE PRECISION NOT NULL,
  speed DOUBLE PRECISION,
  heading DOUBLE PRECISION,
  accuracy DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS locations_trip_ts ON locations (trip_id, ts DESC);
CREATE TABLE IF NOT EXISTS costs (
  id SERIAL PRIMARY KEY,
  trip_id INT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'other',
  amount_cents INT NOT NULL DEFAULT 0,
  note TEXT DEFAULT '',
  ts TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pods (
  id SERIAL PRIMARY KEY,
  trip_id INT UNIQUE NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  receiver_name TEXT NOT NULL,
  note TEXT DEFAULT '',
  signature_png BYTEA,
  lat DOUBLE PRECISION,
  lon DOUBLE PRECISION,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS geocode_cache (
  query TEXT PRIMARY KEY,
  lat DOUBLE PRECISION NOT NULL,
  lon DOUBLE PRECISION NOT NULL,
  label TEXT DEFAULT '',
  ts TIMESTAMPTZ NOT NULL DEFAULT now()
);
`;

async function init() {
  await q(SCHEMA);
  await q(
    `INSERT INTO settings (key, value) VALUES ('company', $1)
     ON CONFLICT (key) DO NOTHING`,
    [JSON.stringify({ name: 'My Transport Company', address: '', vat: '', phone: '', email: '', currency: 'EUR' })]
  );
}

module.exports = { pool, q, init };
