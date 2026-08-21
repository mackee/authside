# authside + a demo app, as a runnable docker compose example

> [!WARNING]
> `authside` is a **FAKE** identity provider for local development and test
> environments only. Never run it in production, or on any host reachable
> from the internet. This example is a demonstration of that fake IdP, not
> a template for a real deployment.

This directory is a self-contained, runnable version of the README's
"As a docker compose sidecar" quick start: `authside` plus a tiny demo
relying party (`app/`) that performs a real OpenID Connect login against it
using `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` -- the same
production code path a real application would use. Nothing about the login
flow is faked on the client side; only the identity provider is.

## The `/etc/hosts` caveat -- read this first

The issuer configured in [`authside.yaml`](./authside.yaml) is
`http://authside:5556/oidc`. An issuer is one string that has to mean the
same thing to two different parties:

- **The demo app**, inside the compose network, resolves `authside` to the
  `authside` container via Docker's embedded DNS and reaches it directly on
  port 5556.
- **Your browser**, on the host, has no idea what `authside` is unless you
  tell it. Docker's DNS is invisible outside the compose network.

Simple mode (see the main README's
["Issuer, mount and advertise"](../../README.md#issuer-mount-and-advertise))
only works when `authside` is reachable at that *one* hostname from both
sides, because the discovery document the app fetches from inside the
network is the same document whose `authorization_endpoint` your browser is
then redirected to.

The fix is a line in your host's `/etc/hosts`:

```
127.0.0.1 authside
```

This makes `authside` resolve to `127.0.0.1` on the host, which is exactly
where `compose.yaml`'s `ports: ["5556:5556"]` publishes the container's
port. From inside the compose network, `authside` still resolves to the
container as usual. Same hostname, two different (correct) resolutions.

If you cannot edit `/etc/hosts` (locked-down machine, CI, etc.), this simple
mode does not apply to you -- see the main README's
[Split-horizon dev environments](../../README.md#split-horizon-dev-environments)
section instead. That configures `issuer` as a verified string only, and
adds a target-level `advertise: {internal: ..., browser: ...}` so the app
and the browser are pointed at different base URLs for the endpoints each
of them actually needs to reach. It costs a few more lines of YAML and
means the app can no longer rely on vanilla `oidc.NewProvider` discovery
matching what the browser sees, but it removes the `/etc/hosts` requirement
entirely.

## Running it

From this directory:

```console
$ docker compose up --build
```

(Substitute `podman-compose` or another compose-compatible tool if you are
not using Docker; the compose file itself has no Docker-specific bits.)

This builds two images from the repository root:

- `authside`, from the repo's top-level `Dockerfile`
- `app`, the demo relying party, from `app/Dockerfile`

Wait for both to report ready -- `authside` prints its "FAKE identity
provider" banner and a `listening` log line; `app` prints
`discovered provider at http://authside:5556/oidc` once it has successfully
fetched discovery (it retries for up to 30 seconds, so a slower host is
fine).

## What to click

1. Add `127.0.0.1 authside` to `/etc/hosts` (see above) if you have not
   already.
2. Open <http://localhost:8080/login> in a browser.
3. You are redirected to `authside`'s picker at
   `http://authside:5556/oidc/authorize` -- a page with a large orange
   "FAKE identity provider" banner and one button per configured user
   (`user-1` / alice@example.com, `user-2` / bob@example.net).
4. Click a user. `authside` redirects back to
   `http://localhost:8080/auth/callback` with an authorization code.
5. The demo app exchanges the code at `authside`'s token endpoint, verifies
   the ID token's signature, issuer, audience and nonce with
   `go-oidc`'s verifier, and renders the decoded claims -- something like:

   ```json
   {
     "at_hash": "...",
     "aud": "local-app",
     "email": "alice@example.com",
     "email_verified": true,
     "exp": 1234567890,
     "hd": "example.com",
     "iat": 1234567890,
     "iss": "http://authside:5556/oidc",
     "name": "Alice",
     "nonce": "...",
     "sub": "user-1"
   }
   ```

## Tearing down

```console
$ docker compose down
```

Nothing here persists state between runs: `authside` has no database, and this
example configures no signing key, so the JWKS differs on every restart. That
does not affect the example -- the demo app fetches a fresh JWKS via discovery
every run, and `go-oidc` re-fetches it whenever it meets an unfamiliar `kid`.
Set `key_file` on the target if you need a token to survive a restart, or to
be verifiable by something other than the running server (see the README's
[Keys](../../README.md#keys)).
