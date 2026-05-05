# Install

The CyberArmor platform ships as a Docker Compose stack. Bring it up locally
to evaluate, then move to a hardened server when you're ready to host it.

## Local demo

```bash
git clone https://github.com/cyberarmor-ai/cyberarmor.git
cd cyberarmor/infra/docker-compose
cp .env.local-demo.example .env.local-demo  # if not already populated
CYBERARMOR_ENV_FILE=./.env.local-demo \
  docker compose --env-file ./.env.local-demo up -d --build
```

After the stack comes up, the dashboard is available at
[http://localhost:3000](http://localhost:3000).

!!! warning "Local-demo defaults"
    The `.env.local-demo` file ships with placeholder secrets that are safe
    for a local machine but **must not** be reused on a server. Generate
    fresh secrets before any production-style deployment.

## Production install

For a real deployment, follow the [Deployment guide](../operations/deployment.md).
It covers host hardening, secrets management, TLS, and the `caddy`-based
reverse proxy that fronts the stack.
