# Dockerfile for Warden
# Use a lightweight Python base image
FROM python:3.12-slim

# Create a non‑root user to run the application
RUN addgroup --system --gid 10001 warden && \
    adduser --system --uid 10001 --ingroup warden warden

# Set working directory
WORKDIR /app

# Install the package and its dependencies
# Copy only the files needed for installation
COPY pyproject.toml README.md LICENSE ./
COPY warden ./warden

# Install the Warden package (includes template assets)
RUN pip install --no-cache-dir .

# Runtime directories must exist and be writable by the unprivileged user.
RUN mkdir -p /config /etc/warden /var/lib/warden && \
    chown -R warden:warden /config /etc/warden /var/lib/warden

# Switch to the non‑root user
USER warden

# Expose default HTTP and HTTPS ports used by Warden
EXPOSE 8080 8443

# By default run the server; configuration can be supplied via WARDEN_CONFIG env var
CMD ["warden", "serve"]