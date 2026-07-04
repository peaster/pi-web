---
"@jmfederico/pi-web": minor
---

Add a `pi-web-docker uninstall` command that stops and removes the Docker runtime stack and the built image. Pass `--purge-data` to also delete the persistent data and install directory (reading their locations from the generated `.env`). The command runs only from the host and is intentionally not exposed through the in-app Docker command surface.
