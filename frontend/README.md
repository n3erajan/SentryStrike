<div align="center">

# SentryStrike Frontend

[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](https://vite.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![React Router](https://img.shields.io/badge/React%20Router-7-CA4245?logo=reactrouter&logoColor=white)](https://reactrouter.com)

</div>
The single-page application your team actually touches. It is where you register a workspace, point the scanner at an application, watch a scan move through its phases live, triage the findings it lands, and export the report. It talks to the backend over a session cookie and renders everything the pipeline produces: crawl coverage, evidence grades, AI verdicts, remediation state, and the audit trail.

## Stack

- React 19 + React DOM
- React Router 7 for routing
- Vite 8 for dev server and builds
- Tailwind CSS 4 through the Vite plugin
- Motion for animation, Lucide for icons
- Nginx serving the production bundle and proxying the API

## What it does

| Area     | Screens                                                                                                         |
| -------- | --------------------------------------------------------------------------------------------------------------- |
| Public   | Landing, login, invite-based registration, request-access, privacy, terms                                       |
| Home     | Workspace dashboard and activity                                                                                |
| Apps     | Application inventory, per-app scan defaults, scan history                                                      |
| Scan     | Scan launch (crawl depth, browser mode, test accounts, per-scan overrides)                                      |
| Scans    | Live and historical scans: phase, progress, ETA, cancellation, worker health                                    |
| Findings | Triage: review status, evidence, AI verdict, assignment, comments, remediation state, one-click re-verification |
| Reports  | Completed reports with severity rollups and PDF download                                                        |
| Team     | Members, roles, invitations, seat usage                                                                         |
| Settings | Workspace settings, audit log, data retention                                                                   |

Routes are declared in `src/App.jsx`. Public routes render standalone; authenticated routes render inside the shared application layout behind a `ProtectedRoute`.

## Development

Prerequisites: Node.js 20.19+ (or 22.12+), and a SentryStrike backend on `http://localhost:8000`.

```bash
npm ci
cp .env.example .env    # points VITE_API_URL at the local backend
npm run dev
```

Open `http://localhost:5173`. The app calls the backend at the origin in `VITE_API_URL`, so the backend's CORS must allow `http://localhost:5173` with credentials (the session cookie is cross-origin in dev).

## Environment

The only variable is `VITE_API_URL`, the backend API base URL, which Vite bakes into the bundle at build time.

```dotenv
VITE_API_URL=http://localhost:8000/api/v1
```

| Variable       | Example                        | Purpose                                        |
| -------------- | ------------------------------ | ---------------------------------------------- |
| `VITE_API_URL` | `http://localhost:8000/api/v1` | Backend API base URL baked into the Vite build |

In development the frontend (:5173) and backend (:8000) are different origins, so requests are cross-origin and need credentials allowed. For an API on a separate host, set the full origin, for example `https://api.example.com/api/v1`. When the frontend and API share an origin behind a reverse proxy, use a relative value instead:

```dotenv
VITE_API_URL=/api/v1
```

The Docker image defaults to `/api/v1` and lets nginx proxy to the backend service.

## Scripts

| Command           | Purpose                                     |
| ----------------- | ------------------------------------------- |
| `npm run dev`     | Vite dev server with hot module replacement |
| `npm run build`   | Production bundle in `dist/`                |
| `npm run preview` | Serve the production bundle locally         |
| `npm run lint`    | ESLint across the project                   |
| `npm test`        | Node-based utility tests                    |

## Project structure

```
src/
  components/    layout, navigation, dialogs, controls, motion primitives
  context/       auth and theme providers
  hooks/         scan, scan-status, health, active-scan state
  pages/         route-level screens
  services/      API modules and the shared HTTP client
  utils/         report filtering, reverify policy, formatting, cURL helpers
  App.jsx        route tree
  main.jsx       entry point and provider composition
```

The shared API client in `src/services/apiClient.js` sends the backend's HttpOnly session cookie, unwraps the `{ success, message, data }` envelope, and centralizes unauthorized-session handling. Tokens are never stored in browser storage.

## Production image

`Dockerfile` builds the Vite bundle and serves it with nginx. `nginx.conf` provides SPA fallback, immutable caching for content-hashed assets, and `/api/` + `/oast/` proxying to `backend:8000` with raised read timeouts for long-running report and analysis requests.

```bash
docker build --build-arg VITE_API_URL=/api/v1 -t sentrystrike-frontend .
```

## Quality checks

Run these before opening a pull request:

```bash
npm test
npm run lint
npm run build
```
