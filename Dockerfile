FROM python:3.11-slim@sha256:f9fa7f851e38bfb19c9de3afbc4b86ae7176ea7aaf94535c31df5458d5849457
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY linuxhound ./linuxhound
ARG INSTALL_GNN=false
RUN if [ "$INSTALL_GNN" = "true" ]; then python -m pip install --no-cache-dir '.[gnn]'; else python -m pip install --no-cache-dir .; fi
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["linuxhound"]
CMD ["--help"]
