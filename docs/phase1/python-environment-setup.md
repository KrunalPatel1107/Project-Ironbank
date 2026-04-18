# Setup: Python Environment

!!! abstract "💰 Cost: $0"

## Install Python 3

=== "Ubuntu/WSL"
    ```bash
    sudo apt install python3 python3-pip python3-venv -y
    python3 --version    # Should show 3.10+
    pip3 --version       # Python's package manager
    ```

=== "macOS"
    ```bash
    brew install python3
    python3 --version
    ```

## Create a Virtual Environment

A virtual environment keeps each project's packages separate — professional practice.

```bash
mkdir -p ~/projects/python-security && cd ~/projects/python-security

# Create isolated Python copy for this project
python3 -m venv venv

# Activate it (prompt changes to show "(venv)")
source venv/bin/activate

# Install packages here — they only affect THIS project
pip install requests boto3

# To deactivate when done:
deactivate
```

??? note "Why virtual environments?"
    If Project A needs library v1.0 and Project B needs v2.0, virtual environments prevent conflicts. Each project gets its own isolated Python. This is like having separate Azure subscriptions for different projects.

## Install VS Code Python Extension

1. VS Code → Extensions → search "Python" → Install (Microsoft)
2. When you open a `.py` file, VS Code auto-detects your virtual environment

## Checklist

- [ ] Python 3.10+ installed
- [ ] pip installed
- [ ] Virtual environment created and activated
- [ ] VS Code Python extension installed
