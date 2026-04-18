# Setup: Linux Environment

!!! abstract "💰 Cost: $0"
    All three options below are free. Pick ONE.

## Option A: WSL2 on Windows (Recommended)

Gives you real Ubuntu Linux inside Windows. No virtual machine needed.

**Step 1: Open PowerShell as Administrator**

Right-click the Windows Start button → click "Terminal (Admin)" or "PowerShell (Admin)"

**Step 2: Install WSL2**

```powershell
wsl --install
```

!!! info "What this does"
    Downloads and installs Ubuntu Linux inside your Windows (~1GB). Takes 5–10 minutes. Your computer may restart.

**Step 3: Create your Linux user**

After restart, Ubuntu opens automatically and asks for a username and password.

- Pick any username (e.g., `user`)
- Pick a password — **you won't see characters as you type** (this is normal Linux behavior, not a bug)

**Step 4: Verify it works**

```bash
cat /etc/os-release   # Should show "Ubuntu" and a version number
```

**Step 5: Update packages (always do this first!)**

```bash
sudo apt update && sudo apt upgrade -y
```

??? note "What each part means (click to expand)"
    - `sudo` = "Super User DO" — runs the command with admin privileges (like "Run as Administrator" in Windows)
    - `apt` = Ubuntu's package manager (like an app store for command-line tools)
    - `update` = download the latest list of available software
    - `&&` = "and then" — run the next command only if the first succeeds
    - `upgrade -y` = install all available updates, `-y` = auto-answer "yes" to prompts

---

## Option B: macOS Terminal (Already Built In)

Your Terminal app already works for 95% of Linux commands.

1. Open Spotlight (Cmd+Space) → type "Terminal" → press Enter
2. Install Homebrew (package manager):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
3. Install common tools:
   ```bash
   brew install wget nmap tree jq
   ```

---

## Option C: AWS EC2 Free Tier

Launch a real Ubuntu server in the cloud.

1. Go to [aws.amazon.com/free](https://aws.amazon.com/free/) → Create a free account
2. In the AWS Console → search "EC2" → Launch Instance
3. **Name:** `linux-practice`
4. **AMI:** Ubuntu Server 24.04 LTS (Free tier eligible)
5. **Instance type:** `t2.micro` (Free tier eligible)
6. **Key pair:** Create new → name it `linux-key` → download the .pem file
7. Launch instance
8. Connect: Click the instance → Connect → use EC2 Instance Connect (browser-based SSH)

!!! danger "💰 Cost: $0 for 12 months ONLY if you manage it"
    - 750 free hours/month of t2.micro for 12 months
    - After 12 months: ~$8/month if left running
    - **Set a calendar reminder!**

!!! abstract "🧹 Cleanup After Each Practice Session"
    ```bash
    # STOP the instance (pauses compute billing):
    # AWS Console → EC2 → Select instance → Instance State → Stop
    # You still pay ~$0.08/month for disk (negligible)

    # To PERMANENTLY delete when no longer needed:
    # Instance State → Terminate (irreversible!)
    ```

---

## Install VS Code

1. Download [Visual Studio Code](https://code.visualstudio.com/) (FREE)
2. Install these extensions (click Extensions icon on left sidebar → search):
    - **Remote - WSL** (if using WSL2 — lets VS Code edit files inside Linux)
    - **Bash IDE** (syntax highlighting for Bash scripts)
    - **Python** (for Month 2)
3. If using WSL2: In your Ubuntu terminal, type `code .` to open VS Code connected to Linux

---

## Checklist

- [ ] Linux environment running (WSL2, Mac Terminal, or EC2)
- [ ] Can open a terminal and see a prompt like `user@laptop:~$`
- [ ] Ran `sudo apt update && sudo apt upgrade -y` (or `brew` on Mac)
- [ ] VS Code installed with extensions
- [ ] If using EC2: know how to Stop and Start the instance
