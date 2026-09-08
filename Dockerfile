# Builder stage.
FROM python:3.14.7-alpine3.24 AS builder

WORKDIR /app

# Set environment variables to reduce writing to disk and improve performance.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create and activate the virtual environment.
RUN python -m venv /opt/build-venv
ENV PATH="/opt/build-venv/bin:$PATH"

# Upgrade pip and install requirements.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# Runtime stage.
FROM alpine:3.24 AS runtime

LABEL org.opencontainers.image.authors="Anthony Farina"

WORKDIR /app

# Patch alpine packages and install clean Python runtime.
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache python3

# Set environment variables to reduce writing to disk and improve performance.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create and activate the virtual environment.
RUN python -m venv --without-pip /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy ONLY the installed dependencies and entrypoint scripts from builder.
COPY --from=builder /opt/build-venv/lib/python3.14/site-packages /opt/venv/lib/python3.14/site-packages
COPY --from=builder /opt/build-venv/bin /opt/venv/bin

# Remove pip and setuptools from the runtime image to reduce size and potential vulnerabilities.
RUN rm -rf \
    /usr/local/lib/python3.14/site-packages/pip* \
    /usr/local/lib/python3.14/site-packages/setuptools* \
    /usr/local/lib/python3.14/ensurepip/_bundled/setuptools* \
    /opt/venv/lib/python3.14/site-packages/pip* \
    /opt/venv/lib/python3.14/site-packages/setuptools*

# Copy source code.
COPY ./src .

# Set non-root user and group to run the app.
RUN addgroup -S -g 10015 prtg_meraki_snow_sync && \
    adduser -S -u 10014 -G prtg_meraki_snow_sync prtg_meraki_snow_sync
USER prtg_meraki_snow_sync:prtg_meraki_snow_sync

# Set the entry for the container to run the app.
ENTRYPOINT ["python", "prtg_meraki_snow_sync.py"]