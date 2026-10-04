# Dependencies

Every package in this application's runtime tree, `requirements.txt`,
chosen directly or brought in by another. Each was checked against the
public registry: the name resolves to the canonical project named here,
not a lookalike. Versions live in the lockfile, not here. The doctrine
job fails when the tree holds a package with no row, or a row names a
package the tree no longer holds (build-doctrine D-039).

| Package | Canonical source | Role | Brought in by |
|---|---|---|---|
| alembic | github.com/sqlalchemy/alembic | schema migrations from the first table | chosen directly |
| annotated-doc | github.com/fastapi/annotated-doc | Document parameters, class attributes, return types, and variables inline, with Annotated | fastapi |
| annotated-types | github.com/annotated-types/annotated-types | Reusable constraint types to use with typing.Annotated | pydantic |
| anyio | github.com/agronholm/anyio | High-level concurrency and networking framework on top of asyncio or Trio | starlette, watchfiles |
| bcrypt | github.com/pyca/bcrypt | password hashing, used directly, maintained by the Python Cryptographic Authority | chosen directly |
| click | github.com/pallets/click | Composable command line interface toolkit | uvicorn |
| fastapi | github.com/fastapi/fastapi | web framework; typed validation as the default path | chosen directly |
| h11 | github.com/python-hyper/h11 | A pure-Python, bring-your-own-I/O implementation of HTTP/1.1 | uvicorn |
| httptools | github.com/MagicStack/httptools | A collection of framework independent HTTP protocol utils | uvicorn |
| idna | github.com/kjd/idna | Internationalized Domain Names in Applications (IDNA) | anyio |
| jinja2 | github.com/pallets/jinja | the report engine, escaping by default (D-040) | chosen directly |
| mako | docs.makotemplates.org | A super-fast templating language that borrows the best ideas from the existing templating languages | alembic |
| markupsafe | github.com/pallets/markupsafe | Safely add untrusted strings to HTML/XML markup | jinja2, mako |
| opentelemetry-api | github.com/open-telemetry/opentelemetry-python | OpenTelemetry Python API | fastapi |
| psycopg | github.com/psycopg/psycopg | PostgreSQL driver | chosen directly |
| psycopg-binary | github.com/psycopg/psycopg | PostgreSQL database adapter for Python -- C optimisation distribution | psycopg |
| pydantic | github.com/pydantic/pydantic | Data validation using Python type hints | fastapi, pydantic-settings |
| pydantic-core | github.com/pydantic/pydantic/tree/main/pydantic-core | Core functionality for Pydantic validation and serialization | pydantic |
| pydantic-settings | github.com/pydantic/pydantic-settings | fail-fast configuration | chosen directly |
| python-dotenv | github.com/theskumar/python-dotenv | Read key-value pairs from a .env file and set them as environment variables | pydantic-settings, uvicorn |
| python-multipart | github.com/Kludex/python-multipart | upload parsing for the two import routes | chosen directly |
| pyyaml | github.com/yaml/pyyaml | YAML parser and emitter for Python | uvicorn |
| sqlalchemy | github.com/sqlalchemy/sqlalchemy | Database Abstraction Library | chosen directly, alembic |
| starlette | github.com/Kludex/starlette | The little ASGI library that shines | fastapi |
| typing-extensions | github.com/python/typing_extensions | Backported and Experimental Type Hints for Python 3.9+ | alembic, fastapi, opentelemetry-api, pydantic, pydantic-core, sqlalchemy, typing-inspection |
| typing-inspection | github.com/pydantic/typing-inspection | Runtime typing introspection tools | fastapi, pydantic, pydantic-settings |
| uvicorn | github.com/Kludex/uvicorn | application server | chosen directly |
| uvloop | github.com/MagicStack/uvloop | Fast implementation of asyncio event loop on top of libuv | uvicorn |
| watchfiles | github.com/samuelcolvin/watchfiles | Simple, modern and high performance file watching and code reload in python | uvicorn |
| websockets | websockets.readthedocs.io/en/stable/project/changelog.html | An implementation of the WebSocket Protocol (RFC 6455 & 7692) | uvicorn |

## Adoption records

Packages read in full when they arrived, beyond the registry check.

### opentelemetry-api

Read October 5, 2026, when FastAPI 0.142 brought it into this tree.

- Registry: the name resolves to the OpenTelemetry project,
  github.com/open-telemetry/opentelemetry-python, under the Cloud Native
  Computing Foundation; license Apache-2.0, compatible with this
  repository's license.
- The project, read by build-doctrine's `scripts/vet.py`: Scorecard 7.8
  of 10; Best Practices passing. Scorecard's vulnerability count, 48,
  belongs to the project's repository; the version installed here has no
  known vulnerability in the OSV database.
- The package: pure Python, no compiled code, no install-time code, one
  dependency (typing-extensions, already in the tree). It imports no
  module that opens a connection or a process; it uses urllib.parse to
  encode strings, and `requests` appears only in documentation
  examples. Without an SDK, which nothing here installs, its providers
  are the no-op ones, so it records and sends nothing.
- Pinned to: the hash in requirements.txt. Fetched through: the registry,
  hash verified on install.
- Runs with: the application's process, no secret, no egress of its own.
- Accepted by: Terry Taylor, on merge of the pull request that added
  this record.
- Expires: October 5, 2027, or when a release adds a dependency or an
  SDK is installed, whichever comes first.
