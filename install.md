# Installation

## 1. Python

The Revocation service was tested with

+ Python version 3.12 and 3.13 (the Docker image uses 3.13)

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The Revocation service was tested with

+ Flask v. 3.1

and should only be used with Flask v. 3.1 or higher.

To install [Flask](https://flask.palletsprojects.com/en/3.1.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/3.1.x/installation/).

## 3. How to run the Revocation service?

To run the Revocation service, please follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.


1. Clone the Revocation service repository:

    ```shell
    git clone git@github.com:eu-digital-identity-wallet/eudi-srv-statuslist-py.git
    ```

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudi-srv-statuslist-py
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```


4. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```


5. Install Flask and other dependencies in the virtual environment

    ```shell
    pip install -r app/requirements.txt
    ```

6. Configure the service

    Copy `app/config_statuslist_example.yaml` to `/etc/statuslist_config/config_statuslist.yaml`
    (or anywhere, and point `STATUS_LIST_CONFIG_PATH` to it) and set at least:

    - `api_key`: the key the issuer sends as `X-Api-Key` (at least 32 random characters);
    - `service_url`: the public base URL the lists are served under;
    - `countries`: the signing key and certificate of every country;
    - `status_list_dir`, `backup_dir` and `logging.path`: writable directories.

    Every key and its default is described in the example file.

7. Run the Revocation Service

    On the root directory of the clone repository, insert one of the following command lines to run the Revocation Service.

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000>)

    ```
    flask --app app run
    ```

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000> with flag debug)

    ```
    flask --app app run --debug
    ```
## 4. Run with Docker

The image `ghcr.io/eu-digital-identity-wallet/eudi-srv-statuslist-py` is built by `.github/workflows/pipeline.yml`
(`:latest` from `main`, `:branch-<name>` from each `branch-*`, `:<version>` from `v*` tags). To build it locally:

```shell
docker build -t eudi-srv-statuslist-py .
```

`docker-compose.yml` runs it on host port 5002. Before `docker compose up -d`:

1. Write the configuration to `/etc/statuslist_config/config_statuslist.yaml` (see step 6 above).
   Inside the container, the default `status_list_dir`, `backup_dir` and `logging.path` are the mounted directories.
2. Put the signing keys and certificates where the `countries` paths point (`/etc/eudiw/...`); they are mounted read-only.
3. Create the list, backup and log directories and give them to the container user:
   `sudo mkdir -p /var/opt/status_lists_dev /var/opt/status_list_backup_dev /var/log/status_lists_dev && sudo chown -R 10001 /var/opt/status_lists_dev /var/opt/status_list_backup_dev /var/log/status_lists_dev`.
4. Set `service_url` to the public URL of the service (or of the web server in front of it): the signed
   lists are fetched there (see "Serving the lists" below).

The lists are kept on disk under a lock (`status_list_dir/state/`), so several containers or `flask run`
processes on the same directories are safe; only one of them renews the lists at a time.

## 5. Serving the lists

The URIs handed to the issuer are `<service_url>token_status_list/<CC>/<doctype>/<id>` and
`<service_url>identifier_list/<CC>/<doctype>/<id>`. The service answers them from `status_list_dir`:
the status list as a JWT (`application/statuslist+jwt`), or as a CWT when the request has
`Accept: application/statuslist+cwt`, and the identifier list as a CWT (`application/identifierlist+cwt`).
These routes are not authenticated and send `ETag`, `Last-Modified`, `Cache-Control: no-cache` and
`Access-Control-Allow-Origin: *`; nothing else under `status_list_dir` (`full_list.json`, `state/`) is served.

A web server in front of the service may serve the lists itself instead. It must then answer the same way
and never serve anything else under `status_list_dir`. A sample nginx configuration, with the service on
port 5002 and the default `status_list_dir` (adapt both):

```nginx
map $http_accept $status_list_file {
    default                         token_status_list.jwt;
    "~application/statuslist\+cwt"  token_status_list.cwt;
}

server {
    # ...
    location ~ "^/token_status_list/(?<cc>[A-Z0-9]+)/(?<doctype>[^/]+)/(?<id>[0-9a-f-]{36})$" {
        root /var/opt/status_lists_dev;
        types { application/statuslist+jwt jwt; application/statuslist+cwt cwt; }
        add_header Vary Accept;
        add_header Access-Control-Allow-Origin *;
        try_files /token_status_list/$cc/$doctype/$id/$status_list_file =404;
    }
    location ~ "^/identifier_list/(?<cc>[A-Z0-9]+)/(?<doctype>[^/]+)/(?<id>[0-9a-f-]{36})$" {
        root /var/opt/status_lists_dev;
        types { application/identifierlist+cwt cwt; }
        add_header Access-Control-Allow-Origin *;
        try_files /identifier_list/$cc/$doctype/$id/identifier_list.cwt =404;
    }
    # take / set / get / swagger
    location /token_status_list/ {
        proxy_pass http://127.0.0.1:5002;
    }
}
```

## 6. Upgrading and repairing lists

The lists are renewed (re-signed from their `full_list.json`) at the hours of `renewal.hours`. A signed
list expires `status_list_validity` seconds (default 24 hours) after it was signed, and relying parties
reject an expired list: keep at least one instance of the service running, so that the lists are
renewed. The service refuses to start with a key that is not EC P-256, a certificate that does not
match its key, or an invalid numeric setting. To renew
at once, for instance after an upgrade, to repair lists damaged by earlier versions (trailing bytes after
the CWT or the JWT signature, lists that were never renewed):

```shell
flask --app app:create_app renew-lists        # or: docker compose exec status_list flask renew-lists
```

It prints how many lists were renewed and removed (expired), and lists the ones it could not renew;
a list whose `full_list.json` itself is damaged cannot be rebuilt. It exits with status 1 if any.
