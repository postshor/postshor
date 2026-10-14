FROM python:3.12-slim

LABEL org.opencontainers.image.title="PostShor" \
      org.opencontainers.image.description="Find quantum-vulnerable cryptography and plan the migration to post-quantum standards" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/postshor/postshor"

WORKDIR /opt/postshor
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home scanner

USER scanner
WORKDIR /src
ENTRYPOINT ["postshor"]
CMD ["scan", "."]
