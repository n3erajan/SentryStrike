# SentryStrike Frontend

The SentryStrike frontend is a React single-page application for managing web applications, launching authorized assessments, monitoring live progress, reviewing findings, coordinating remediation, and exporting completed reports.

## Stack

- React 19 and React DOM
- React Router 7
- Vite 8
- Tailwind CSS 4 through the Vite plugin
- Lucide icons
- Nginx for the production image

## User workflows

- Invite-based registration and cookie-backed login
- Workspace dashboard and application inventory
- Single-page or full-site scan submission with optional test accounts
- Active scan progress, phase, ETA, cancellation, and worker-health visibility
- Finding review, assignment, comments, remediation status, and focused re-verification
- Completed report filtering, AI-analysis status, and PDF download
- Team membership, roles, invitations, audit history, and retention settings

Routes are declared in [`src/App.jsx`](src/App.jsx). Public routes cover the landing, login, and registration screens; authenticated routes render inside the shared application layout.

## Development

### Prerequisites

- Node.js 20.19+ or 22.12+
- A SentryStrike backend running on `http://localhost:8000`

```bash
npm ci
cp .env.example .env   # points VITE_API_URL at the local backend
npm run dev
```

Open <http://localhost:5173>. The app calls the backend directly at the origin set in `VITE_API_URL`, so the backend's CORS must allow `http://localhost:5173` with credentials.

## Environment

The app reads `VITE_API_URL`, the backend API base URL, which Vite bakes into the bundle at build time. Copy the template and adjust if your backend lives elsewhere:

```bash
cp .env.example .env
```

```dotenv
VITE_API_URL=http://localhost:8000/api/v1
```

| Variable | Example | Purpose |
| --- | --- | --- |
| `VITE_API_URL` | `http://localhost:8000/api/v1` | Backend API base URL baked into the Vite build |

In development the frontend (`http://localhost:5173`) and backend (`http://localhost:8000`) are different origins, so requests are cross-origin — the backend must allow the frontend origin with credentials (the auth session cookie). For an API on a separate host, set the full origin, e.g. `https://api.example.com/api/v1`.

When the frontend and API share an origin behind a reverse proxy, use a relative value instead:

```dotenv
VITE_API_URL=/api/v1
```

The Docker image defaults to `/api/v1` and lets Nginx proxy requests to the backend service (see [Production image](#production-image)).

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start Vite with hot module replacement |
| `npm run build` | Create the production bundle in `dist/` |
| `npm run preview` | Serve the production bundle locally |
| `npm run lint` | Run ESLint across the project |
| `npm test` | Run the Node-based utility tests |

## Project structure

```text
src/
├── components/    Layout, navigation, dialogs, controls, and feedback
├── context/       Authentication and theme providers
├── hooks/         Scan, scan-status, health, and active-scan state
├── pages/         Route-level application screens
├── services/      Typed-by-convention API modules and the shared HTTP client
├── utils/         Report filtering, policy, formatting, and cURL helpers
├── App.jsx        Route tree
└── main.jsx       Browser entry point and provider composition
```

The shared API client in [`src/services/apiClient.js`](src/services/apiClient.js) includes the backend's HttpOnly session cookie, unwraps `{ success, message, data }` responses, and centralizes unauthorized-session handling. Tokens are not stored in browser storage.

## Production image

[`Dockerfile`](Dockerfile) builds the Vite bundle and serves it with Nginx. [`nginx.conf`](nginx.conf) provides SPA fallback, immutable asset caching, and `/api/` proxying to `backend:8000`.

```bash
docker build --build-arg VITE_API_URL=/api/v1 -t sentrystrike-frontend .
```

## Quality checks

Run all frontend checks before opening a pull request:

```bash
npm test
npm run lint
npm run build
```
