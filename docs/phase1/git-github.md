# Month 1 — Week 4: Git, GitHub & Project

!!! abstract "💰 Cost: $0 — GitHub is free for public repos"

!!! info "Goal"
    Learn Git version control, create a GitHub account, and publish your CIS audit script as your first portfolio piece.

## Day 15: Install & Configure Git

```bash
# Install Git
sudo apt install git -y        # Ubuntu/WSL
# brew install git              # macOS

# Verify
git --version                  # Should show git version 2.x

# Configure your identity (one-time setup)
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
git config --global init.defaultBranch main   # Use "main" not "master"
```

??? note "What is Git?"
    Git tracks changes to your files over time — like a save system for code. Every time you `commit`, Git takes a snapshot. You can go back to any previous snapshot, see who changed what, and work with others without overwriting each other's work. GitHub is a website that hosts your Git repositories online.

---

## Day 16: Your First Repository

### Step 1: Create the project folder

```bash
mkdir -p ~/projects/cis-audit
cd ~/projects/cis-audit

# Copy your scripts from Week 3
cp ~/scripts/cis_audit.sh .
cp ~/scripts/hello.sh .
```

### Step 2: Create a README

Every GitHub project needs a README.md that explains what it does:

```bash
cat > README.md << 'EOF'
# 🔒 CIS Benchmark Audit Script

A Bash script that audits Ubuntu/Debian servers against CIS security benchmarks.

## What It Checks

- SSH configuration (root login, password auth, MaxAuthTries)
- File permissions (/etc/shadow, /etc/passwd)
- Empty password detection
- Firewall status (UFW)
- Automatic security updates
- SUID files in /tmp
- Password aging policy

## Usage

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cis-audit.git
cd cis-audit

# Make executable and run
chmod +x cis_audit.sh
sudo ./cis_audit.sh
```

## Sample Output

```
============================================
  CIS Benchmark Audit — myserver
  Date: Sat Apr 10 09:00:00 UTC 2026
============================================

[PASS] SSH root login is disabled
[PASS] /etc/shadow permissions: 640 (correct)
[PASS] No users with empty passwords
[FAIL] No firewall active! Fix: sudo ufw enable
[PASS] Unattended upgrades installed
[PASS] No SUID files in /tmp
[WARN] SSH MaxAuthTries not set — set to 4

============================================
  Results: 5 PASS | 1 FAIL | 1 WARN
============================================
```

## Author

Your Name — Security Professional learning Cloud/AppSec
- [LinkedIn](https://linkedin.com/in/your-linkedin-profile/)

## License

MIT
EOF
```

### Step 3: Initialize Git and make your first commit

```bash
# Initialize a Git repository in this folder
git init
# Output: Initialized empty Git repository in /home/user/projects/cis-audit/.git/

# Stage all files (prepare them for saving)
git add .
# The . means "everything in the current directory"

# Commit (save a snapshot)
git commit -m "Initial commit: CIS audit script and README"
# -m = message describing what changed
```

??? note "Git vocabulary"
    - `git init` = start tracking this folder
    - `git add .` = "stage" files (mark them for the next save)
    - `git commit -m "message"` = save a snapshot with a description
    - `git status` = see what's changed since last commit
    - `git log` = see history of all commits
    - `git diff` = see exactly what changed in files

### Step 4: Push to GitHub

1. Go to [github.com](https://github.com) → Sign up (FREE) or log in
2. Click the **+** icon (top right) → **New repository**
3. **Repository name:** `cis-audit`
4. **Description:** "CIS Benchmark audit script for Ubuntu servers"
5. **Visibility:** Public (so employers can see it!)
6. **⚠️ Do NOT** check "Initialize with README" (you already have one)
7. Click **Create repository**

GitHub shows you commands. Run these in your terminal:

```bash
git remote add origin https://github.com/YOUR_USERNAME/cis-audit.git
git push -u origin main
# You'll be asked for your GitHub username and password
# For password, use a Personal Access Token (not your actual password):
# GitHub → Settings → Developer settings → Personal access tokens → Generate new token
```

!!! success "Your code is now on GitHub!"
    Visit `https://github.com/YOUR_USERNAME/cis-audit` to see it. The README renders as a beautiful page. This is portfolio piece #1.

---

## Day 17: Making Changes and Pushing Updates

```bash
# Make a change to your script (add a new check)
nano cis_audit.sh
# ... add your improvements ...

# See what changed
git status
# Output: modified: cis_audit.sh

# See the exact changes
git diff cis_audit.sh

# Stage, commit, and push
git add cis_audit.sh
git commit -m "Add password aging policy check"
git push
```

The workflow you'll use forever: **edit → add → commit → push**

---

## Day 18–19: SSH Analyzer Script (Second Portfolio Piece)

Add the SSH analyzer from Week 2-3 to your repo:

```bash
# Copy and add it
cp ~/scripts/ssh_analyzer.sh .
git add ssh_analyzer.sh
git commit -m "Add SSH brute force analyzer script"
git push
```

Update the README to mention both scripts.

---

## 🧹 Cleanup

All work is local + on GitHub. No cloud costs.

```bash
# Your projects stay in ~/projects/cis-audit/
# Your scripts stay in ~/scripts/
# Both are safely backed up on GitHub now

# If using EC2: STOP the instance
# AWS Console → EC2 → Instance State → Stop
```

---

## ✅ Month 1 Complete Checklist

- [ ] Git installed and configured
- [ ] GitHub account created
- [ ] Understand: `init`, `add`, `commit`, `push`, `status`, `diff`, `log`
- [ ] `cis-audit` repository pushed to GitHub with README
- [ ] README has: description, usage instructions, sample output
- [ ] Made at least 2 commits (initial + update)
- [ ] Completed OverTheWire Bandit Levels 0–15
- [ ] Completed TryHackMe Linux Fundamentals (3 rooms)
- [ ] All EC2 instances STOPPED (if used)

!!! success "🎉 Month 1 Complete!"
    You can now navigate Linux, process logs, write scripts, and use Git. Proceed to **Month 2: Python**.
