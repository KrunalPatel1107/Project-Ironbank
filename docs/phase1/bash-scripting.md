# Month 1 — Week 3: Bash Scripting

!!! abstract "💰 Cost: $0 — All local"

!!! info "Goal"
    Write your first scripts — from a simple hello world to a security audit tool. A Bash script is just a text file with commands that Linux runs top to bottom.

## Day 11: Your Absolute First Script

### Step 1: Create the script file

```bash
mkdir -p ~/scripts && cd ~/scripts

# Open nano text editor (simplest terminal editor)
nano hello.sh
```

!!! tip "How to use nano"
    When nano opens, you just type. **Save:** press `Ctrl+O` then `Enter`. **Exit:** press `Ctrl+X`. That's all you need.

### Step 2: Type this content

```bash
#!/bin/bash
# hello.sh — My first script
# Line 1 (#!/bin/bash) is the "shebang" — tells Linux to use Bash

# VARIABLES — store values (NO spaces around the = sign!)
NAME="Alex"
DATE=$(date)           # $(...) runs a command and saves the output
HOSTNAME=$(hostname)

# PRINT — echo sends text to the screen
echo "=================================="
echo "  Hello, $NAME!"              # $NAME gets replaced with "Alex"
echo "  Date:     $DATE"
echo "  Hostname: $HOSTNAME"
echo "=================================="

# IF/ELSE — make decisions
if [ -f /etc/shadow ]; then       # -f = "does this FILE exist?"
    echo "✅ /etc/shadow exists"
else
    echo "❌ /etc/shadow missing!"
fi                                # "fi" ends the if block (it's "if" backwards)

# FOR LOOP — repeat something for each item in a list
echo ""
echo "Checking important files:"
for FILE in /etc/passwd /etc/shadow /etc/hosts; do
    if [ -f "$FILE" ]; then
        PERMS=$(stat -c "%a" "$FILE" 2>/dev/null)
        echo "  ✅ $FILE — permissions: $PERMS"
    else
        echo "  ❌ $FILE — NOT FOUND"
    fi
done                              # "done" ends the for loop
```

### Step 3: Run it

```bash
chmod +x hello.sh   # Add execute permission (+x = executable)
./hello.sh           # ./ means "run this file in current directory"
```

!!! success "Expected output"
    ```
    ==================================
      Hello, Alex!
      Date:     Sat Apr 10 09:00:00 UTC 2026
      Hostname: laptop
    ==================================
    ✅ /etc/shadow exists

    Checking important files:
      ✅ /etc/passwd — permissions: 644
      ✅ /etc/shadow — permissions: 640
      ✅ /etc/hosts — permissions: 644
    ```

---

## Day 12: Script Arguments & Input Validation

Scripts can accept inputs from the command line:

```bash
#!/bin/bash
# greet.sh — Accept arguments
# Usage: ./greet.sh Alex 30

NAME="${1:-World}"     # $1 = first argument. Default: "World" if none given
AGE="${2:-unknown}"    # $2 = second argument. Default: "unknown"

echo "Hello, $NAME! You are $AGE years old."

# Special variables:
# $0 = the script's own filename
# $1, $2, $3... = arguments passed to the script
# $# = number of arguments
# $@ = all arguments
# $? = exit code of last command (0 = success, non-zero = error)
```

```bash
./greet.sh Alex 30    # Output: Hello, Alex! You are 30 years old.
./greet.sh            # Output: Hello, World! You are unknown years old.
```

### Input validation (secure coding practice!)

```bash
#!/bin/bash
# validate.sh — Always validate your inputs

LOG_FILE="${1}"

# Check if argument was provided
if [ -z "$LOG_FILE" ]; then           # -z = "is this string EMPTY?"
    echo "ERROR: No log file specified."
    echo "Usage: $0 <logfile>"
    exit 1                            # Exit with error code 1
fi

# Check if the file actually exists
if [ ! -f "$LOG_FILE" ]; then         # ! = NOT, -f = file exists?
    echo "ERROR: File '$LOG_FILE' not found."
    exit 1
fi

echo "Processing $LOG_FILE..."
# ... rest of script
```

---

## Days 13–14: CIS Hardening Audit Script (Monthly Project)

This is your first portfolio piece. Build a script that checks 7+ security settings:

```bash
#!/bin/bash
# cis_audit.sh — Ubuntu CIS Benchmark Security Checker
# Usage: sudo ./cis_audit.sh

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'          # NC = No Color (reset)

# === COUNTERS ===
PASS=0; FAIL=0; WARN=0

# === FUNCTIONS (reusable code blocks) ===
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN+1)); }

echo "============================================"
echo "  CIS Benchmark Audit — $(hostname)"
echo "  Date: $(date)"
echo "============================================"
echo ""

# CHECK 1: SSH Root Login Disabled
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    pass "SSH root login is disabled"
else
    fail "SSH root login NOT disabled — fix: set PermitRootLogin no in /etc/ssh/sshd_config"
fi

# CHECK 2: /etc/shadow permissions
if [ -f /etc/shadow ]; then
    SP=$(stat -c "%a" /etc/shadow)
    if [ "$SP" = "640" ] || [ "$SP" = "600" ]; then
        pass "/etc/shadow permissions: $SP (correct)"
    else
        fail "/etc/shadow permissions: $SP — should be 640. Fix: sudo chmod 640 /etc/shadow"
    fi
fi

# CHECK 3: No users with empty passwords
EP=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$EP" ]; then
    pass "No users with empty passwords"
else
    fail "Users with EMPTY passwords: $EP"
fi

# CHECK 4: Firewall active
if sudo ufw status 2>/dev/null | grep -q "active"; then
    pass "UFW firewall is active"
else
    fail "No firewall active! Fix: sudo ufw enable"
fi

# CHECK 5: Automatic security updates
if dpkg -l 2>/dev/null | grep -q unattended-upgrades; then
    pass "Unattended upgrades installed"
else
    warn "Auto-updates not installed — sudo apt install unattended-upgrades"
fi

# CHECK 6: No SUID files in /tmp
SUID=$(find /tmp -perm -4000 2>/dev/null | wc -l)
if [ "$SUID" -eq 0 ]; then
    pass "No SUID files in /tmp"
else
    fail "$SUID SUID files in /tmp — privilege escalation risk!"
fi

# CHECK 7: SSH MaxAuthTries
MAT=$(grep -i "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ -n "$MAT" ] && [ "$MAT" -le 4 ]; then
    pass "SSH MaxAuthTries: $MAT"
else
    warn "SSH MaxAuthTries not set or too high — set to 4 in /etc/ssh/sshd_config"
fi

# === SUMMARY ===
echo ""
echo "============================================"
echo -e "  Results: ${GREEN}$PASS PASS${NC} | ${RED}$FAIL FAIL${NC} | ${YELLOW}$WARN WARN${NC}"
echo "============================================"
```

??? note "New concepts explained"
    - `echo -e` = enable escape characters (needed for `\033[0;31m` color codes)
    - `-q` in grep = "quiet" — don't print output, just check if pattern exists
    - `-z "$VAR"` = true if the variable is empty (zero length)
    - `-n "$VAR"` = true if the variable is NOT empty
    - `-eq` = "equals" for number comparison inside `[ ]`
    - `-le` = "less than or equal to" for numbers
    - `2>/dev/null` = redirect error messages to nowhere (suppress errors)
    - `stat -c "%a"` = get file permissions as a number (e.g., 644)
    - `find /tmp -perm -4000` = find files with SUID bit set
    - `$((PASS+1))` = arithmetic in Bash

### Challenge: Add More Checks

Try adding these yourself before moving to Week 4:

- [ ] Check password aging policy: `grep PASS_MAX_DAYS /etc/login.defs`
- [ ] Check for world-writable directories: `find / -type d -perm -0002 2>/dev/null`
- [ ] Check if `root` is the only UID 0 user: `awk -F: '($3 == 0) {print $1}' /etc/passwd`
- [ ] Check kernel version: `uname -r`
- [ ] Check for listening services: `ss -tlnp`

---

## 🧹 Cleanup

All scripts are on your local machine. No cloud resources.

```bash
# Keep your scripts! They're going to GitHub next week.
ls ~/scripts/    # hello.sh, greet.sh, validate.sh, cis_audit.sh
```

---

## ✅ Checklist

- [ ] Wrote `hello.sh` with variables, if/else, and for loops
- [ ] Understand the shebang line (`#!/bin/bash`)
- [ ] Can use `chmod +x` and run scripts with `./`
- [ ] Understand `$1`, `$2`, `$@`, `$?` (script arguments and exit codes)
- [ ] Can do input validation (`-z`, `-f`, `exit 1`)
- [ ] Wrote `cis_audit.sh` with 7+ security checks
- [ ] Script outputs colored PASS/FAIL/WARN with summary
- [ ] Added 2+ additional checks as challenge exercises
