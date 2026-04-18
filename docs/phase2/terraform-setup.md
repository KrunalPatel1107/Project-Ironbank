# Setup: Install Terraform

!!! abstract "💰 Cost: $0"

=== "Ubuntu/WSL"
    ```bash
    sudo apt install -y gnupg software-properties-common
    wget -O- https://apt.releases.hashicorp.com/gpg | \
      sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
      https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
      sudo tee /etc/apt/sources.list.d/hashicorp.list
    sudo apt update && sudo apt install terraform -y
    ```

=== "macOS"
    ```bash
    brew install terraform
    ```

```bash
# Verify
terraform --version   # Should show 1.6+

# Also install security scanners
pip install checkov   # IaC security scanner
```

!!! tip "What is Terraform?"
    Terraform is **declarative** — you describe the end state ("I want a VPC with 2 subnets") and Terraform figures out the steps. Contrast with the AWS CLI commands from Month 4 which are **imperative** ("create this, then create that, then attach this"). Terraform is like saying "I want a peanut butter sandwich" vs giving step-by-step kitchen instructions.

## Checklist

- [ ] Terraform installed (`terraform --version` works)
- [ ] Checkov installed (`checkov --version` works)
