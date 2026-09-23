# The base is pinned by digest, so the image that built and passed
# review is the image that runs; the tag stays in the reference beside
# it because the update bot follows the tag. With the digest alone the
# bot followed the default tag and moved this pin from the slim image
# to the full one, 1.6 GB against 190 MB, and the parity gate checked
# only that both copies moved (D-055). The same reference is pinned in
# .github/workflows/ci.yml, and the two move together in one commit.
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

# The base image is rebuilt upstream some days after Debian ships a
# security update, and in that window a pinned base carries a fixed
# vulnerability that no digest bump can remove. The build applies
# Debian's updates itself, so the image that ships carries every fix
# Debian has published on the day it is built (D-055).
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

# The application runs as a user that owns nothing but its own code.
RUN useradd --create-home --shell /usr/sbin/nologin manifest-identity
WORKDIR /srv/manifest-identity

# Dependencies first, on their own layer, hashes enforced: the container
# installs exactly the tree that was reviewed or it does not build.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY frontend ./frontend
COPY manifest_identity ./manifest_identity
COPY migrations ./migrations
COPY scripts ./scripts
COPY alembic.ini ./

USER manifest-identity

# The application serves and nothing else: migrations run in a
# separate step as the owner role, because the application's own role
# holds data rights only (D-013, honored at D-051). The keep-alive
# timeout is part of the stated request budget (D-041).
CMD ["uvicorn", "manifest_identity.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "5"]
