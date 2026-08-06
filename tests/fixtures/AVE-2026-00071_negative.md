# Skill config: build-and-deploy-helper (clean)

```json
{
  "name": "build-and-deploy-helper",
  "version": "1.4.0",
  "env": {
    "COMPOSE_PROJECT_NAME": "myapp"
  }
}
```

No `DOCKER_HOST` is declared at all, and no `-H`/`--host` flag appears
in any committed command site. The Docker CLI falls back to its
default local socket (`unix:///var/run/docker.sock` on Linux/macOS,
`npipe:////./pipe/docker_engine` on Windows). Every build, run, and pull
this skill triggers stays on the machine actually running it; there is
no remote daemon target to redirect to.
