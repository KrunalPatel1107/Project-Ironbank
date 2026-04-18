# Month 2 — Week 1: Python Fundamentals

!!! abstract "💰 Cost: $0"

!!! info "Why Python for security work?"
    Python is the #1 language used by security professionals. It lets you automate boring tasks (checking 100 servers at once instead of one by one), talk to cloud APIs like AWS, parse log files, and build security tools. You don't need any prior programming experience — this week builds everything from scratch.

## What is a Python script?

A Python script is just a plain text file (ending in `.py`) that contains instructions. When you run it, Python reads those instructions top-to-bottom and executes them. That's it.

Think of it like a Bash script (which you wrote in Week 3 of Month 1), but Python is much more powerful and easier to read.

??? note "Python vs Bash — when to use which?"
    - **Bash scripts** (`.sh`): Great for quick automation — running commands, moving files, checking if services are running. Like a fast checklist.
    - **Python scripts** (`.py`): Better for anything complex — talking to APIs, parsing structured data (JSON), doing calculations, building real tools. Like a full program.

    You'll use both. This month is Python.

---

## Day 6: Setup & Your First Script

### Install Python

```bash
# Check if Python 3 is already installed
python3 --version
# If you see "Python 3.x.x" — you're ready!
# If not, install it:
sudo apt install python3 python3-pip -y    # Ubuntu/WSL

# Create a folder for your Python work
mkdir -p ~/projects/python-security
cd ~/projects/python-security

# Create your first virtual environment
# (This is a private space for installing Python packages, so they don't
#  interfere with your system. Best practice — always use one!)
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
# You'll see (venv) at the start of your prompt — that means it's active
# (venv) user@laptop:~/projects/python-security$

# When you're done working, deactivate with:
# deactivate
```

!!! tip "Always activate your venv before working on Python scripts"
    Run `source venv/bin/activate` each time you open a new terminal and want to work on Python. The `(venv)` prefix tells you it's active.

### Your very first Python script

```bash
# Create the file
nano fundamentals.py
```

Type (or paste) this into nano, then save with Ctrl+O, Enter, Ctrl+X:

```python
# fundamentals.py — my first Python script
# Lines starting with # are COMMENTS — Python ignores them.
# Use comments to explain what your code does.

# ============================================================
# PART 1: VARIABLES
# A variable is a named box that holds a value.
# You create one by: variable_name = value
# ============================================================

name = "Alex"          # A string (text goes in quotes)
age = 30               # An integer (whole number, no quotes)
is_certified = True    # A boolean — True or False (capital T/F!)

# print() shows output on the screen — it's how Python talks back to you
print(name)            # Output: Alex
print(age)             # Output: 30
print(is_certified)    # Output: True

# f-strings: put variable values INSIDE text
# Put an f before the quote, then use {variable_name} inside
print(f"My name is {name} and I am {age} years old.")
# Output: My name is Alex and I am 30 years old.
```

```bash
# Run your script:
python3 fundamentals.py
```

!!! success "Expected output"
    ```
    Alex
    30
    True
    My name is Alex and I am 30 years old.
    ```

---

## Day 7: Lists & Dictionaries

Add this to the bottom of `fundamentals.py`:

```python
# ============================================================
# PART 2: LISTS
# A list is an ordered collection of items, in square brackets.
# Like a shopping list — items in a specific order.
# ============================================================

skills = ["Sentinel", "Defender", "IAM"]  # A list of 3 strings

print(skills)           # Output: ['Sentinel', 'Defender', 'IAM']
print(skills[0])        # Output: Sentinel   (0 = first item!)
print(skills[1])        # Output: Defender   (1 = second item)
print(skills[2])        # Output: IAM        (2 = third item)

# len() tells you how many items are in the list
print(len(skills))      # Output: 3

# Add an item to the end of the list
skills.append("Python")
print(skills)           # Output: ['Sentinel', 'Defender', 'IAM', 'Python']

# ============================================================
# PART 3: DICTIONARIES
# A dictionary stores key → value pairs, in curly braces.
# Like a real dictionary: word → definition
# Or like a form: field name → field value
# ============================================================

server = {
    "hostname": "web-01",    # key: "hostname",  value: "web-01"
    "ip": "10.0.1.5",        # key: "ip",        value: "10.0.1.5"
    "ports": [22, 80, 443]   # key: "ports",     value: a LIST of ports
}

# Access a value by its key (in square brackets)
print(server["hostname"])    # Output: web-01
print(server["ip"])          # Output: 10.0.1.5
print(server["ports"])       # Output: [22, 80, 443]

# f-strings work with dictionary lookups too
print(f"Server {server['hostname']} is at {server['ip']}")
# Output: Server web-01 is at 10.0.1.5

# Add a new key-value pair
server["os"] = "Ubuntu 22.04"
print(server)
```

---

## Day 8: If/Else & For Loops

Add this to the bottom of `fundamentals.py`:

```python
# ============================================================
# PART 4: IF / ELIF / ELSE
# Make decisions based on conditions.
# CRITICAL RULE: Python uses INDENTATION (spaces) to define
# what is "inside" a block. Always use 4 spaces.
# ============================================================

# You've already seen this concept in Bash:
#   if [ condition ]; then
#       ...
#   fi
#
# Python is the same idea, just different syntax:
#   if condition:
#       ...       ← 4 spaces indent
#   else:
#       ...

score = 75

if score >= 90:
    print("Grade: A")           # Only runs if score >= 90
elif score >= 80:
    print("Grade: B")           # Only runs if score >= 80 AND score < 90
elif score >= 70:
    print("Grade: C")           # This runs! 75 is >= 70
else:
    print("Grade: F")           # Runs if NOTHING above was true

# Output: Grade: C

# Checking if something is in a list:
if "IAM" in skills:
    print("IAM is in your skills list!")

# Checking the number of items:
if len(skills) > 3:
    print(f"You have {len(skills)} skills — that's a lot!")

# ============================================================
# PART 5: FOR LOOPS
# Repeat an action for every item in a list.
# ============================================================

# "for each item in the list, do something"
for skill in skills:             # skill gets assigned each item, one at a time
    print(f"  - {skill}")        # This line runs once per item

# Output:
#   - Sentinel
#   - Defender
#   - IAM
#   - Python

# You can loop over a list of anything
ports_to_check = [22, 80, 443, 8080]
for port in ports_to_check:
    if port == 22:
        print(f"Port {port}: SSH — keep restricted!")
    elif port == 80:
        print(f"Port {port}: HTTP — consider forcing HTTPS")
    else:
        print(f"Port {port}: open")
```

!!! tip "The indentation rule is Python's most important rule"
    Unlike Bash (which uses `if/fi`, `for/done`), Python uses **indentation** to show what's "inside" a block. Always use exactly **4 spaces** per level. If your indentation is wrong, Python will give you an `IndentationError`. This trips up everyone at first — just be consistent.

---

## Day 9: Functions

Add this to the bottom of `fundamentals.py`:

```python
# ============================================================
# PART 6: FUNCTIONS
# A function is a reusable block of code you give a name to.
# You "define" it once, then "call" it as many times as you want.
# This is like a Bash function (you used these in cis_audit.sh!)
#
# In Bash:    pass() { echo "PASS: $1"; }
# In Python:  def pass_check(message):
#                 print(f"PASS: {message}")
# ============================================================

# Define a function with "def":
def greet(person_name):           # "person_name" is a parameter (the input)
    """Say hello to a person."""   # This string describes what the function does
    print(f"Hello, {person_name}!")

# Call the function (actually run it):
greet("Alex")       # Output: Hello, Alex!
greet("World")      # Output: Hello, World!

# Functions can RETURN a value (give something back to the caller):
def check_permission(score):
    """Return access level based on score."""
    if score >= 90:
        return "Admin"
    elif score >= 70:
        return "User"
    else:
        return "Denied"

level = check_permission(75)  # The returned value goes into "level"
print(f"Access level: {level}")   # Output: Access level: User

# A more useful function for security work:
import os    # "import" loads a built-in Python module (like a toolbox)
             # "os" = operating system tools (file checks, paths, etc.)

def check_file_exists(path):
    """Check if a file exists and return a status string."""
    if os.path.exists(path):       # os.path.exists() → True or False
        return f"✅ {path} exists"
    else:
        return f"❌ {path} MISSING"

print(check_file_exists("/etc/shadow"))   # ✅ /etc/shadow exists
print(check_file_exists("/etc/fake"))     # ❌ /etc/fake MISSING
```

---

## Day 10: File I/O and Error Handling

Create a new file for this:

```bash
nano file_practice.py
```

```python
# file_practice.py — reading and writing files

# ============================================================
# WRITING TO A FILE
# open(filename, mode) opens a file.
# Mode "w" = write (creates the file, or OVERWRITES if it exists)
# Mode "a" = append (adds to end, doesn't overwrite)
# Mode "r" = read (read only)
#
# The "with" statement: automatically closes the file when done.
# Without it, you'd have to remember to call f.close() yourself.
# If your script crashes before f.close(), the file might get corrupted.
# "with" prevents that — always use it.
# ============================================================

with open("audit_report.txt", "w") as f:    # f is the "file handle" (a nickname)
    f.write("=== Audit Report ===\n")        # \n = newline (go to next line)
    f.write("Server: web-01\n")
    f.write("IP: 10.0.1.5\n")

print("File written!")

# ============================================================
# READING A FILE
# ============================================================

with open("audit_report.txt", "r") as f:
    content = f.read()               # Read the entire file as one big string
    print(content)

# Read line by line (better for large files):
with open("audit_report.txt", "r") as f:
    for line in f:                   # f acts like a list of lines
        print(f"Line: {line.strip()}")  # .strip() removes the \n at end

# ============================================================
# ERROR HANDLING with try / except
# When something might go wrong, wrap it in try/except.
# This prevents your script from crashing on errors.
# Same concept as Bash's "2>/dev/null" but more powerful.
# ============================================================

try:
    with open("nonexistent_file.txt", "r") as f:
        content = f.read()
except FileNotFoundError:
    # This runs if the file doesn't exist
    print("File not found — that's okay, we handled it!")
except PermissionError:
    # This runs if we don't have permission to read the file
    print("Permission denied!")
except Exception as e:
    # This catches ANY other error
    # "e" contains the error message
    print(f"Unexpected error: {e}")

print("Script finished — no crash!")
```

```bash
python3 file_practice.py
```

!!! success "Expected output"
    ```
    File written!
    === Audit Report ===
    Server: web-01
    IP: 10.0.1.5

    Line: === Audit Report ===
    Line: Server: web-01
    Line: IP: 10.0.1.5
    File not found — that's okay, we handled it!
    Script finished — no crash!
    ```

---

## Full Script: Putting It All Together

Here's a small security tool that uses everything from this week:

```bash
nano security_check.py
```

```python
# security_check.py — a mini security checker using this week's concepts

import os    # for file existence checks

# --- FUNCTION DEFINITIONS ---

def check_file(path, expected_perms):
    """
    Check if a file exists and has the right permissions.
    path          = the file to check (e.g. "/etc/shadow")
    expected_perms= the permission number we want (e.g. "640")
    Returns a string: PASS or FAIL with details.
    """
    if not os.path.exists(path):
        return f"❌ MISSING: {path} does not exist"

    # stat -c "%a" gets permissions as a number (like 640, 644, etc.)
    # os.popen() runs a shell command and gives us the output
    perms = os.popen(f"stat -c '%a' {path}").read().strip()

    if perms == expected_perms:
        return f"✅ PASS: {path} has permissions {perms}"
    else:
        return f"❌ FAIL: {path} has {perms} (expected {expected_perms})"

# --- MAIN LOGIC ---

# List of (file, expected permissions) pairs to check
files_to_check = [
    ("/etc/passwd",  "644"),   # readable by everyone, that's fine
    ("/etc/shadow",  "640"),   # only root + shadow group
    ("/etc/hosts",   "644"),
]

results = []    # Empty list — we'll add results to it

for file_path, expected in files_to_check:
    result = check_file(file_path, expected)   # call our function
    results.append(result)                     # add result to our list
    print(result)                              # show it on screen

# Save results to a file
with open("check_results.txt", "w") as f:
    for result in results:
        f.write(result + "\n")     # \n adds a newline after each line

print("\nResults saved to check_results.txt")
```

```bash
python3 security_check.py
```

---

## Study Resources

- [Automate the Boring Stuff](https://automatetheboringstuff.com/) — Chapters 1–8 (FREE online, best beginner Python book)
- [Python for Everybody](https://www.youtube.com/watch?v=x7Krla_UxRg) — 14-hour video (FREE, very beginner-friendly)

!!! tip "How to approach the study resources"
    Don't try to read everything at once. Read a chapter, then practice by modifying the scripts on this page. The best way to learn programming is to *break* things and fix them.

---

## ✅ Checklist

- [ ] Python 3 and virtual environment set up and working
- [ ] Can run a `.py` file with `python3 filename.py`
- [ ] Understand variables: `name = "Alex"`, `age = 30`, `is_certified = True`
- [ ] Understand lists: `skills = ["a", "b", "c"]`, `skills[0]`, `len(skills)`, `skills.append(x)`
- [ ] Understand dictionaries: `server = {"key": "value"}`, `server["key"]`
- [ ] Understand if/elif/else with 4-space indentation
- [ ] Understand for loops: `for item in list:`
- [ ] Can define and call a function with `def`
- [ ] Can read and write files with `with open()`
- [ ] Can handle errors with `try / except`
- [ ] Wrote `security_check.py` and it runs without errors
- [ ] Completed "Automate the Boring Stuff" Chapters 1–6
