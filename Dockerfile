# The base is pinned by digest, not by tag, so the image that built and
# passed review is the image that runs. The digest resolves the
# python:3.14-slim tag; moving it is a reviewed change. The same digest
# is pinned in .github/workflows/ci.yml, and the two move together:
# automated update tools only see this file, so the workflow pin is
# updated by hand in the same commit.
FROM python@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

# The base image is rebuilt upstream some days after Debian ships a
# security update, and in that window a pinned base carries a fixed
# vulnerability that no digest bump can remove. The build applies
# Debian's updates itself, so the image that ships carries every fix
# Debian has published on the day it is built (D-055).
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

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
