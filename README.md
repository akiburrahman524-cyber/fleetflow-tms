# FleetFlow TMS

A lightweight transport management system (TMS) for small fleets. Free and open stack:
Node.js + Express + PostgreSQL, Leaflet with OpenStreetMap maps, Chart.js. No paid services.

## Features

- Dashboard: open orders, active trips, free trucks, monthly margin, revenue-vs-cost chart, live fleet map
- Customers, orders (pickup/delivery with map geocoding), trucks, drivers
- Trips: assign truck + driver + orders, status flow (planned → loading → in transit → completed), timeline
- Live GPS: driver opens a share link on their phone (no login), shares browser location; office sees the truck moving on the map
- Documents: DDT (Documento di Trasporto) and POD (Proof of Delivery) PDFs; POD signed on the driver's phone with signature capture
- Costs per trip (fuel/toll/other), reports per truck/driver/customer, CSV export
- Demo data clearly marked, removable in Settings

## Run

```bash
npm install
DATABASE_URL=postgres://user:pass@host/db node server.js
```

First visit opens the owner setup screen (company + account). Then optionally load demo data from Settings.

## Deploy (Render free)

- New Web Service from this repo
- Build command: `npm install`
- Start command: `node server.js`
- Environment: `DATABASE_URL` (Neon free PostgreSQL connection string)
