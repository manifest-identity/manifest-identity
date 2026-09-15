# The base is pinned by digest, not by tag, so the image that built and
# passed review is the image that runs. The digest resolves the
# python:3.14-slim tag; moving it is a reviewed change. The same digest
# is pinned in .github/workflows/ci.yml, and the two move together:
# automated update tools only see this file, so the workflow pin is
# updated by hand in the same commit.
FROM python@sha256:e06cc1111ed84189e91866447f562b89faadbfbbb9937cd67e6bf4172cdb45df

# The application runs as a user that owns nothing but its own code.
RUN useradd --create-home --shell /usr/sbin/nologin rolecall
WORKDIR /srv/rolecall

# Dependencies first, on their own layer, hashes enforced: the container
# installs exactly the tree that was reviewed or it does not build.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY frontend ./frontend
COPY rolecall ./rolecall
COPY migrations ./migrations
COPY scripts ./scripts
COPY alembic.ini ./

USER rolecall

# The application serves and nothing else: migrations run in a
# separate step as the owner role, because the application's own role
# holds data rights only (D-013, honored at D-051). The keep-alive
# timeout is part of the stated request budget (D-041).
CMD ["uvicorn", "rolecall.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "5"]
