# Single-stage: slim base, no build toolchain in the final image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DAWNPATROL_DATA_DIR=/var/lib/dawnpatrol \
    DAWNPATROL_OUTPUT_DIR=/out \
    DAWNPATROL_PROFILE=/etc/dawnpatrol/profile.yml

RUN useradd --system --uid 10001 --create-home --home-dir /home/dawnpatrol dawnpatrol

WORKDIR /app

# Dependencies first, so a source edit does not invalidate the install layer.
COPY pyproject.toml README.md ./
COPY dawnpatrol/__init__.py ./dawnpatrol/
RUN pip install --no-cache-dir ".[all]"

COPY dawnpatrol/ ./dawnpatrol/
RUN pip install --no-cache-dir --no-deps -e . \
    && mkdir -p /var/lib/dawnpatrol /out /etc/dawnpatrol \
    && chown -R dawnpatrol:dawnpatrol /var/lib/dawnpatrol /out /app

USER dawnpatrol

VOLUME ["/var/lib/dawnpatrol", "/out"]

# Exits non-zero when the scheduler has stopped ticking, so a wedged
# container is visible to Docker rather than merely silent.
HEALTHCHECK --interval=5m --timeout=15s --start-period=1m --retries=3 \
    CMD ["python", "-m", "dawnpatrol.cli", "healthcheck"]

ENTRYPOINT ["python", "-m", "dawnpatrol.cli"]
CMD ["serve"]
