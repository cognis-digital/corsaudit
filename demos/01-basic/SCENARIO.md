# Demo 01 - Basic: origin reflection with credentials

This demo shows CORSAUDIT detecting the classic, high-impact CORS
misconfiguration: the server **reflects the request `Origin`** back into
`Access-Control-Allow-Origin` **and** sets `Access-Control-Allow-Credentials:
true`. A browser will then let *any* site (including an attacker's) read the
victim's credentialed responses.

> Defensive / authorized-testing only. CORSAUDIT performs **no** network
> requests. It analyzes headers you have already captured (e.g. via your
> browser devtools or an authorized scan you ran against an app you own).

## Input

`response_headers.txt` is a saved response-header block from a preflight/probe
request in which the `Origin: https://attacker.example` header was sent.

## Run it

Table output:

```sh
python -m corsaudit headers demos/01-basic/response_headers.txt \
    --origin https://attacker.example
```

JSON output (for piping into CI / dashboards):

```sh
python -m corsaudit --format json headers demos/01-basic/response_headers.txt \
    --origin https://attacker.example
```

## Expected result

- Rule **CORS002** (critical): "Origin reflection with credentials".
- Rule **CORS008** (medium): state-changing methods (PUT/DELETE) allowed with
  credentials.
- Exit code **1** (findings present), so it fails a CI gate.

## Remediation

Validate the incoming `Origin` against a strict allowlist before echoing it,
and never combine credentialed responses with reflected/arbitrary origins.
