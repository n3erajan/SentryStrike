# SentryStrike Frontend

The SentryStrike frontend is a React single-page application for managing web applications, launching authorized assessments, monitoring live progress, triaging findings, and exporting completed reports.

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
npm run dev
```

Open <http://localhost:5173>. Vite proxies `/api` to the local backend, so the default development flow remains same-origin.

## Environment

Copy the example when the API is served from a different origin:

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_API_URL` | `/api/v1` | Backend API base URL baked into the Vite build |

For local development, either omit the variable and use Vite's proxy or set it to `http://localhost:8000/api/v1`. Production builds normally keep `/api/v1` and let Nginx proxy requests to the backend service.

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
