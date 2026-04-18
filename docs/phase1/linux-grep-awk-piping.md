# Month 1 — Week 2: grep, awk & Piping

!!! abstract "💰 Cost: $0 — All local commands"

!!! info "Goal"
    Search, filter, and transform text data. These are the exact tools SOC analysts use on Linux servers. Your Splunk SPL / Sentinel KQL experience transfers directly.

## Day 6: grep — Search for Patterns

`grep` searches for text patterns in files. This will be your most-used security tool on Linux.

### Create a practice log file

```bash
cat > sample.log << 'EOF'
2024-04-10 09:15 INFO  User admin logged in from 192.168.1.10
2024-04-10 09:16 ERROR Failed login for root from 10.0.0.5
2024-04-10 09:17 INFO  User admin accessed /api/users
2024-04-10 09:18 ERROR Failed login for admin from 203.0.113.50
2024-04-10 09:19 WARN  Disk usage at 85%
2024-04-10 09:20 ERROR Failed login for root from 203.0.113.50
2024-04-10 09:21 INFO  User admin logged out
2024-04-10 09:22 ERROR Failed login for root from 203.0.113.50
2024-04-10 09:23 ERROR Failed login for admin from 203.0.113.50
2024-04-10 09:25 INFO  Backup completed successfully
EOF
```

### Basic grep commands

```bash
# Find all lines containing "ERROR"
grep "ERROR" sample.log
# Output: Shows all 5 ERROR lines

# Case-insensitive search
grep -i "error" sample.log        # -i = ignore case (finds ERROR, Error, error)

# Count matches
grep -c "Failed" sample.log       # -c = count. Output: 5

# Show line numbers
grep -n "Failed" sample.log       # -n = line numbers

# Invert match (show lines that DON'T contain the pattern)
grep -v "INFO" sample.log         # -v = invert. Shows ERROR and WARN only

# Search for a specific IP address
grep "203.0.113.50" sample.log    # Find all activity from this suspicious IP

# Combine: find failed logins from the suspicious IP
grep "Failed" sample.log | grep "203.0.113.50"
# The | (pipe) sends output of first command as input to second
```

!!! tip "Sentinel/Splunk Parallel"
    - `grep "Failed" sample.log` = Splunk: `index=main "Failed"`
    - `grep "Failed" sample.log | grep "203.0.113.50"` = Splunk: `index=main "Failed" "203.0.113.50"`
    - `grep -c "Failed" sample.log` = KQL: `Syslog | where SyslogMessage contains "Failed" | count`

---

## Day 7: Piping & Text Processing (awk, sort, uniq)

The `|` (pipe) symbol is the most powerful concept in Linux. It sends the output of one command as input to the next — like a conveyor belt where each tool does one thing.

### The Security Analysis Pipeline

```bash
# Find which IPs are trying to brute force us
grep "Failed" sample.log | awk '{print $NF}' | sort | uniq -c | sort -rn
```

??? note "Step-by-step breakdown (click to expand)"
    **Step 1:** `grep "Failed" sample.log`

    Filters to only "Failed login" lines (5 lines)

    **Step 2:** `| awk '{print $NF}'`

    `awk` splits each line into "fields" (words separated by spaces).
    `$NF` means "last field" (NF = Number of Fields).
    The last field in our log is the IP address.
    Output: just the IPs, one per line.

    **Step 3:** `| sort`

    Alphabetically sorts the IPs. **Required for `uniq` to work** — `uniq` only counts *consecutive* identical lines.

    **Step 4:** `| uniq -c`

    Counts consecutive identical lines. `-c` = show count before each unique value.
    Output: `   1 10.0.0.5` and `   4 203.0.113.50`

    **Step 5:** `| sort -rn`

    `-r` = reverse order (highest first). `-n` = numeric sort (treat numbers as numbers, not text).

    **Final output:**
    ```
       4 203.0.113.50    ← This IP had 4 failed attempts — likely attacker!
       1 10.0.0.5
    ```

### More awk examples

```bash
# Print specific fields
awk '{print $1, $2}' sample.log     # First 2 fields (date, time)
awk '{print $3}' sample.log          # 3rd field (INFO/ERROR/WARN)

# Print full line if it matches a pattern
awk '/ERROR/ {print $0}' sample.log  # Same as grep "ERROR" but awk-style

# Print with custom formatting
awk '/Failed/ {print "ALERT:", $NF, "at", $2}' sample.log
# Output: ALERT: 10.0.0.5 at 09:16
#         ALERT: 203.0.113.50 at 09:18
#         ...
```

---

## Day 8: Networking Commands

```bash
# What ports are OPEN on your machine?
ss -tlnp
# -t = show TCP connections only
# -l = show only LISTENING ports (waiting for connections)
# -n = show port numbers (not names like "http")
# -p = show which PROCESS owns each port

# Check HTTP security headers of a website
curl -I https://example.com
# -I = HEAD request (headers only, not the full page)
# Look for these security headers:
#   X-Frame-Options          → clickjacking protection
#   Strict-Transport-Security → force HTTPS
#   Content-Security-Policy  → XSS protection
#   X-Content-Type-Options   → MIME sniffing protection
# If these are MISSING → the site has security issues!

# DNS lookup — find what IP a domain points to
dig example.com            # Full DNS response
dig example.com +short     # Just the IP address
dig example.com MX         # Mail server records
dig example.com TXT        # TXT records (SPF, DKIM, etc.)

# Download a file and verify its integrity
wget https://example.com/file.zip
sha256sum file.zip
# Compare the output hash to the published hash
```

---

## Exercises

1. Using `sample.log`, find which **username** was targeted most often
2. Count how many `INFO` vs `ERROR` vs `WARN` lines there are
3. Extract just the timestamps (field 2) of all failed logins
4. Find all unique IP addresses in the log (any line, not just failures)
5. Complete OverTheWire Bandit Levels 5–10

??? example "Solutions (try yourself first!)"
    ```bash
    # 1. Most targeted username
    grep "Failed" sample.log | awk '{print $7}' | sort | uniq -c | sort -rn

    # 2. Count by severity
    awk '{print $3}' sample.log | sort | uniq -c | sort -rn

    # 3. Timestamps of failed logins
    grep "Failed" sample.log | awk '{print $2}'

    # 4. All unique IPs
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' sample.log | sort -u
    # -o = print only the matching part
    # -E = extended regex
    # sort -u = sort and remove duplicates
    ```

---

## 🧹 Cleanup

```bash
rm sample.log    # Delete the practice log file
```

No cloud resources created. No costs.

---

## ✅ Checklist

- [ ] Can use `grep` with `-c`, `-n`, `-v`, `-i` flags
- [ ] Understand piping with `|` and can chain 3+ commands
- [ ] Can use `awk '{print $N}'` to extract specific fields
- [ ] Can use `sort | uniq -c | sort -rn` to count and rank
- [ ] Can use `curl -I` to check HTTP security headers
- [ ] Can use `dig` for DNS lookups
- [ ] Completed OverTheWire Bandit Levels 5–10
- [ ] Completed all 5 exercises above
