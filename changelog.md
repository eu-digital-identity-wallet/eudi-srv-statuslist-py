# Changelog

## [0.9]

_24 Nov 2025_

### Changed
- Update to Token Status List draft 12

### Fixed
- JWT Header

## [0.10.0]

_4 Nov 2026_

### Added
- `.github/workflows/`: `semgrep.yml`, `pipeline.yml` (image on `main`, `branch-*` and `v*` tags), `README.md`, and `.github/CODEOWNERS`.
- `app/log_utils.py`: `safe()` escapes and bounds logged request values.
- YAML configuration (`app/config.py`, `STATUS_LIST_CONFIG_PATH`) with `variables`; keys documented in `app/config_statuslist_example.yaml`.
- `Dockerfile` (non-root), `.dockerignore` and `docker-compose.yml`.
- Unit, concurrency, property (Hypothesis) and regression tests (99% coverage), run by `sonar.yml`.
- `flask renew-lists`: re-signs every list and reports the ones it could not renew.
- `state/<CC>/<doctype>/current.json`: the current list survives restarts and is shared between processes.
- `POST /token_status_list/take/batch` and `/set/batch` (all or nothing, capped by `batch_max_size`, default 1000).
- `allowed_doctypes`: `wrprc` and `oauth-client-attestation+jwt` by default.
- `debug` (default `false`); Flask debug mode was always on.
- `renewal.hours` (default `[0, 12]`) and `status_list_ttl` (default 3600); both were hard-coded.
- `status_list_validity` (default 86400 s): signed lists carry `exp` and `ttl` (draft-12 section 13.7).
- `max_expiry_days` (default 3650) bounds `expiry_date`.
- `logging.path`, `logging.log_level` and `logging.backup_count`.
- `GET /token_status_list/<CC>/<doctype>/<id>` (JWT, or CWT by `Accept`) and `GET /identifier_list/<CC>/<doctype>/<id>` serve the signed lists; nginx is optional.

### Changed
- `gitleaks.yml`, `dependencycheck.yml` and `sonar.yml` run the scans themselves instead of the `eudi-infra-ci` reusable workflows.
- The gitleaks configuration moved to `gitleaks/gitleaks.toml`.
- `ConfService` and the `API_key` environment variable are replaced by the YAML configuration.
- `countries.<CC>` keys and certificates are loaded once at start-up.
- Dependencies upgraded (`pip-audit` clean); unused `requests`, `flask_api`, `cwt` and `flask-cors` removed.
- `token-status-list` (draft-02 alpha) is replaced by `app/status_list.py`; `full_list.json` keeps its format.
- `README.md` references draft-ietf-oauth-status-list-12 instead of draft-02.
- `print()` calls are log records.
- Lists live on disk only, under per-list locks with atomic writes, so several processes can share `status_list_dir`.
- `/take` no longer re-signs the published lists.
- Identifier list `id`s are random (ISO/IEC 18013-5); older tokens keep `str(idx)`. `/get` and `/set` take `idx`, `id` or both.
- `/get` and `/set` errors are JSON; a bad `X-Api-Key` is 401 on every endpoint.
- `/get` and `/set` answer `text/plain`.
- `idx` and `status` must be plain decimal numbers; `status` must be `1`.
- A list `uri` must be spelled as `/take` returned it.
- Expiry dates are UTC days.
- The index allocator picks uniformly among free indices (draft-12 section 12.5.1).
- CWT lists no longer carry the fixed `kid` `"1"` (draft-12 section 11.3).
- `swagger.json` documents every status code and constrains the parameters.
- `token_status_list_size` is documented as a number of entries.
- The log file defaults to `/var/log/status_lists/` instead of world-writable `/tmp/status_lists`.
- Only the published lists are world-readable; other files are `0600`.
- Request bodies are limited to 1 MiB on every endpoint, and `X-Api-Key` is checked before the body is read.
- A failed `X-Api-Key` check is logged on every endpoint.

### Fixed
- `/take` logged `X-Api-Key`.
- A missing, short or placeholder `api_key` was accepted; the key is compared in constant time.
- `/get` and `/set` allowed path traversal through `uri`.
- `/set` with `idx=-1` revoked another credential.
- Concurrent `/set` requests corrupted the published lists and lost revocations (upstream eudi-srv-web-issuing-eudiw-py#191).
- After a `/set`, later `/take` calls on that list failed with 500 until a restart.
- A full list dropped every other in-memory list, and concurrent `/take` calls could share one entry.
- New lists shared one identifier dict, and a new country entry replaced its other doctypes.
- A list that had handed out one index was never renewed.
- Renewal stopped at the first identifier list or the first failing list.
- A second process or a restart undid revocations made elsewhere.
- `/get` on an identifier list always answered 0.
- Learning credential, mVC and tax doctypes were not allowed.
- `install.md` cloned the issuer backend repository and listed gunicorn.
- `gitleaks/gitleaks.toml` failed to load.
- `sonar.yml` analysed pull requests without coverage.
- A wrong stored `num_allocated` made `/take` loop forever or start a list too early.
- Corrupt or deeply nested `full_list.json` raised unhandled errors.
- Renewal removed a list on its credentials' last valid day.
- Wrong key types and mismatched certificates were accepted at start-up.
- Invalid numeric settings were only found at run time.
- Deeply nested or malformed batch bodies answered 500 instead of 400.
- 405 responses had no `Allow` header.
