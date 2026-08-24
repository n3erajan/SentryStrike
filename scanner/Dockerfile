# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Scanner worker image.
#
# The worker drives Playwright/Chromium for browser-based crawling, so it is
# built on the official Playwright Python image whose Chromium build and OS
# libraries are matched to the pinned playwright==1.60.0 wheel. Do NOT bump the
# base tag independently of scanner/requirements.txt - the browser and the
# client library must agree.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/playwright/python:v1.60.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Install Python dependencies first so the layer is cached across code changes.
COPY scanner/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Application code: shared modules then the scanner package.
COPY shared ./shared
COPY scanner/app ./app

# Writable log directory (LOG_FILE defaults to logs/scanner.log) owned by the
# non-root user the Playwright image already provides.
RUN mkdir -p /app/logs && chown -R pwuser:pwuser /app

USER pwuser

# Liveness: the worker process must be running. It has no listening port, so we
# check the process table rather than an HTTP endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD pgrep -f "app.worker" > /dev/null || exit 1

CMD ["python", "-m", "app.worker"]
