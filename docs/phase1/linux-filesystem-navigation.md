# Month 1 — Week 1: Filesystem & Navigation

!!! abstract "💰 Cost: $0 — Everything runs locally"

!!! info "Goal"
    Navigate the Linux filesystem, create/delete files, and understand permissions. Spend 1.5–2 hours daily.

## Day 1: Understanding the Terminal

When you open the terminal, you see something like:

```
user@laptop:~$
```

??? note "What each part means"
    - `user` = your username (who you are)
    - `@laptop` = the machine name (which computer)
    - `~` = your current location (`~` means "home directory", which is `/home/user`)
    - `$` = you're a normal user (if you see `#` instead, you're root/admin — be careful!)

### Your very first commands

```bash
# "Print Working Directory" — shows where you are right now
pwd
# Output: /home/user

# "Who Am I" — shows your username
whoami
# Output: user

# "List" — shows files and folders in current directory
ls
# Output: (might be empty if fresh install, or show Desktop, Documents, etc.)

# List with details (permissions, size, date)
ls -la
# -l = "long" format (show details)
# -a = "all" (include hidden files that start with .)
```

### Navigation

```bash
cd /         # Go to the ROOT of the entire filesystem (top level)
ls           # See what's here: bin, etc, home, var, tmp, usr...

cd /home     # Go to the home folder (where all user folders live)
ls           # You should see your username folder

cd ~         # Go back to YOUR home directory (shortcut)
pwd          # Verify: /home/user

cd ..        # Go UP one level (to parent directory)
pwd          # Now at: /home

cd -         # Go back to the PREVIOUS directory you were in
pwd          # Back at: /home/user
```

!!! tip "Key directories to know"
    - `/` = root of filesystem (everything starts here)
    - `/home` = where user home directories live
    - `/etc` = system configuration files (security-critical!)
    - `/var/log` = system log files (security analysts live here)
    - `/tmp` = temporary files (cleared on reboot)
    - `/usr/bin` = installed programs

---

## Day 2: Creating & Managing Files

```bash
# Create a practice folder
mkdir security-labs        # "Make Directory" — creates a new folder
cd security-labs           # Move into it

# Create empty files
touch notes.txt            # Creates an empty file called notes.txt
touch script.sh config.yml # Create multiple files at once
ls                         # Verify: notes.txt  script.sh  config.yml

# Write text into a file
echo "Hello, this is my first file" > notes.txt
# The > symbol OVERWRITES the file with the text

echo "This is a second line" >> notes.txt
# The >> symbol APPENDS (adds to end) without overwriting

# Read the file
cat notes.txt              # "Concatenate" — prints entire file to screen
# Output:
# Hello, this is my first file
# This is a second line

# Copy a file
cp notes.txt notes_backup.txt    # cp = copy. Format: cp SOURCE DESTINATION

# Rename / Move a file
mv config.yml config.yaml        # mv = move. Also used to rename files

# Delete a file
rm notes_backup.txt              # rm = remove. File is GONE forever.

# Create nested directories
mkdir -p projects/aws/terraform  # -p = create parent directories too

# Delete a directory with contents
rm -rf projects                  # -r = recursive, -f = force
```

!!! danger "NEVER run `rm -rf /` or `rm -rf ~`"
    `rm -rf` permanently deletes with no recycle bin, no undo. Always double-check the path before running it. One wrong character can wipe everything.

---

## Day 3: File Permissions (Security Critical!)

Permissions control who can read, write, and execute files. This is fundamental to Linux security.

```bash
echo "secret password: hunter2" > secret.txt
ls -l secret.txt
# Output: -rw-r--r-- 1 user user 27 Apr 10 09:00 secret.txt
```

??? note "How to read `-rw-r--r--` (click to expand)"
    Split into 4 parts: `-` | `rw-` | `r--` | `r--`

    - Part 1: `-` = file type (`-` = regular file, `d` = directory)
    - Part 2: `rw-` = **Owner** permissions: **r**ead ✅, **w**rite ✅, e**x**ecute ❌
    - Part 3: `r--` = **Group** permissions: read ✅, write ❌, execute ❌
    - Part 4: `r--` = **Others** (everyone else): read ✅, write ❌, execute ❌

    **Number system:** r=4, w=2, x=1. Add them up:

    - `rwx` = 4+2+1 = **7** (full access)
    - `rw-` = 4+2+0 = **6** (read+write)
    - `r--` = 4+0+0 = **4** (read only)
    - `---` = 0+0+0 = **0** (no access)

    So `-rw-r--r--` = **644** in number form.

```bash
# Make readable ONLY by you (remove group and others access)
chmod 600 secret.txt         # 6=rw- for owner, 0=--- for group, 0=--- for others
ls -l secret.txt
# Output: -rw------- 1 user user 27 Apr 10 09:00 secret.txt

# Make a script executable
echo '#!/bin/bash
echo "Hello from my script!"' > myscript.sh
chmod +x myscript.sh         # +x = add execute permission
./myscript.sh                # ./ means "run this file in current directory"
# Output: Hello from my script!

# Security-critical permission checks:
ls -l /etc/shadow            # Should be 640 or 600 (password hashes!)
ls -l /etc/passwd            # Should be 644 (user info, no passwords)
```

---

## Days 4–5: Practice

1. **OverTheWire Bandit Levels 0–10:** [overthewire.org/wargames/bandit](https://overthewire.org/wargames/bandit/)

    ```bash
    # Connect to Bandit Level 0:
    ssh bandit0@bandit.labs.overthewire.org -p 2220
    # Password: bandit0
    # ssh = Secure Shell (remote login)
    # bandit0@ = login as user "bandit0"
    # -p 2220 = connect on port 2220
    ```

    !!! abstract "💰 Cost: $0 — OverTheWire is completely free"

2. **TryHackMe Linux Fundamentals:** [Part 1](https://tryhackme.com/room/linuxfundamentalspart1), [Part 2](https://tryhackme.com/room/linuxfundamentalspart2), [Part 3](https://tryhackme.com/room/linuxfundamentalspart3) (FREE rooms)

3. **Practice exercise** — create this folder structure using only terminal:
    ```bash
    mkdir -p iron-bank/{docs,scripts,configs}
    touch iron-bank/docs/notes.md
    touch iron-bank/scripts/audit.sh
    touch iron-bank/configs/aws.conf
    tree iron-bank/    # If 'tree' not installed: sudo apt install tree
    ```

---

## 🧹 Cleanup

No cloud resources created this week. Clean up practice files if you want:

```bash
rm -rf ~/security-labs
rm -rf ~/iron-bank
```

If you used EC2 (Option C): **Stop the instance** → AWS Console → EC2 → Instance State → Stop.

---

## ✅ Checklist

- [ ] Can run `pwd`, `ls`, `cd`, `mkdir`, `rm` without looking them up
- [ ] Created files with `touch`, `echo >`, `echo >>`
- [ ] Read files with `cat`
- [ ] Copied/moved/renamed files with `cp`, `mv`
- [ ] Understand the permission number system (644, 600, 755)
- [ ] Changed permissions with `chmod`
- [ ] Completed OverTheWire Bandit Levels 0–5
- [ ] Completed TryHackMe Linux Fundamentals Part 1
- [ ] EC2 instance STOPPED (if used)
