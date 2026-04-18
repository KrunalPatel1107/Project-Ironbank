# Setup: Docker

!!! abstract "💰 Cost: $0 — Docker runs locally"

=== "Ubuntu/WSL"
    ```bash
    sudo apt install docker.io docker-compose -y
    sudo usermod -aG docker $USER
    # LOG OUT and log back in for the group change to take effect!

    # Verify
    docker --version
    docker run hello-world    # Should print "Hello from Docker!"
    ```

=== "macOS"
    Download [Docker Desktop](https://www.docker.com/products/docker-desktop/) (FREE for personal use).
    ```bash
    docker --version
    docker run hello-world
    ```

!!! tip "What is Docker?"
    Docker runs applications in isolated "containers" — like lightweight virtual machines. You'll use it to run vulnerable test apps (Juice Shop), security scanners (ZAP), and eventually your own applications. Every container is disposable — delete it and start fresh anytime.

## Checklist

- [ ] Docker installed and `docker --version` works
- [ ] `docker run hello-world` prints the welcome message
