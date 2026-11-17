# Third-party components

PhantomNet's MIT license covers only original PhantomNet code. The components
below are downloaded at build time and keep their own licenses. Verify each
license and version before every release — this table is a starting point,
not legal advice.

| Component | Used for | License (verify) | Source |
|---|---|---|---|
| OpenCanary | SSH / MySQL decoy simulations | BSD-3-Clause | https://github.com/thinkst/opencanary |
| Python (python:3.12-slim-bookworm image) | Runtime | PSF License; Debian packages under their own licenses | https://hub.docker.com/_/python |
| FastAPI | Dashboard | MIT | https://github.com/fastapi/fastapi |
| Uvicorn | ASGI server | BSD-3-Clause | https://github.com/encode/uvicorn |
| Jinja2 | Templates | BSD-3-Clause | https://github.com/pallets/jinja |
| PyYAML | Policy file parsing | MIT | https://github.com/yaml/pyyaml |
| pytest, httpx (dev only) | Tests | MIT, BSD-3-Clause | PyPI |

No third-party source code is vendored in this repository.
