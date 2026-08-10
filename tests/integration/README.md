# VibeConnect Integration Stack

Run the live container stack explicitly:

```sh
docker compose -f tests/integration/docker-compose.yml up --abort-on-container-exit
```

The default unit test gate validates this scaffold statically. Live container execution
is reserved for the integration gate because it depends on local Docker availability.
