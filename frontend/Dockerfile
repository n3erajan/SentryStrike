# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Frontend image: Vite build served by nginx, which also reverse-proxies /api
# to the backend (see nginx.conf).
# ---------------------------------------------------------------------------

# ---- Build stage ---------------------------------------------------------
FROM node:24-alpine AS builder

WORKDIR /app

# VITE_API_URL is baked into the bundle at BUILD time (import.meta.env), so it
# must be supplied here, not at container runtime. Default to the relative
# /api/v1 path which nginx proxies to the backend (same-origin, no CORS).
ARG VITE_API_URL=/api/v1
ENV VITE_API_URL=${VITE_API_URL}

# Install dependencies from the lockfile for reproducible builds.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- Runtime stage -------------------------------------------------------
FROM nginxinc/nginx-unprivileged:stable-alpine

# nginx.conf listens on 8080 (the unprivileged image cannot bind :80 as non-root).
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
