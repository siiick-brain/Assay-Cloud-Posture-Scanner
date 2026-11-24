# assay-cspm scanner image. Runs as a non-root user and works with `docker run --read-only`.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    CSPM_MAPPINGS_DIR=/app/mappings

WORKDIR /app
COPY requirements.lock /app/requirements.lock
# Hashes are mandatory, so a changed or swapped wheel fails the build.
# Pull Debian security fixes that landed after the base image digest was cut.
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*     && pip install --require-hashes --no-deps -r /app/requirements.lock \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin cspm \
    && mkdir /out && chown cspm /out

# The package runs from source on PYTHONPATH, which avoids an unpinned build backend.
COPY cspm /app/cspm
COPY rules /app/rules
COPY mappings /app/mappings
COPY testbed/azure-fixtures /app/testbed/azure-fixtures

USER 10001
VOLUME ["/out"]
ENTRYPOINT ["python", "-m", "cspm.cli.main"]
CMD ["--help"]
