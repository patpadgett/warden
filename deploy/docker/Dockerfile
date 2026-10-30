# Dockerfile for Warden
# Use a lightweight Python base image
FROM python:3.12-slim

# Create a non‑root user to run the application
RUN addgroup --system warden && \
    adduser --system --ingroup warden warden

# Set working directory
WORKDIR /app

# Install the package and its dependencies
# Copy only the files needed for installation
COPY pyproject.toml .
COPY README.md .
COPY warden ./warden

# Install the Warden package (includes template assets)
RUN pip install --no-cache-dir .

# Switch to the non‑root user
USER warden

# Expose default HTTP and HTTPS ports used by Warden
EXPOSE 8080 8443

# By default run the server; configuration can be supplied via WARDEN_CONFIG env var
CMD ["warden", "serve"]