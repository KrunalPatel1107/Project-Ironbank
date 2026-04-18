# Month 2 — Week 2: Files, APIs & Libraries

!!! abstract "💰 Cost: $0"

## What are Python libraries?

Python comes with some built-in tools, but you can also **install extra libraries** — packages of pre-written code that do specific things. Instead of writing thousands of lines yourself, you just import someone else's library and use it.

```bash
# Install extra libraries with pip (Python's package manager)
pip install requests boto3

# "requests" = a library for making HTTP calls (like curl, but in Python)
# "boto3"    = the official AWS library for Python (used in Week 3)
```

At the top of every Python script you'll see `import` lines. This loads a library into your script so you can use its tools:

```python
import json        # loads Python's built-in JSON library
import requests    # loads the installed "requests" library
import os          # loads Python's built-in operating system library
```

---

## Working with JSON

JSON (JavaScript Object Notation) is a text format for structured data. Every AWS API response comes back as JSON. It looks exactly like a Python dictionary:

```json
{
  "hostname": "web-01",
  "ip": "10.0.1.5",
  "secure": true
}
```

```python
# json_practice.py
import json

# Start with a Python dictionary
server = {"hostname": "web-01", "ip": "10.0.1.5", "secure": True}

# Convert the dictionary to a JSON string (for sending over the internet or saving)
# json.dumps() = "dump to string"
# indent=2 = format it nicely with 2-space indentation (easier to read)
json_string = json.dumps(server, indent=2)
print(json_string)
# Output:
# {
#   "hostname": "web-01",
#   "ip": "10.0.1.5",
#   "secure": true
# }

# Convert a JSON string BACK to a Python dictionary
# json.loads() = "load from string"
raw_json = '{"name": "Alex", "role": "Security"}'
data = json.loads(raw_json)
print(data["name"])         # Output: Alex
print(type(data))           # Output: <class 'dict'>  ← it's a Python dict now!

# Save a dictionary to a JSON FILE
with open("server_data.json", "w") as f:
    json.dump(server, f, indent=2)    # json.dump() = "dump to file"
print("Saved to server_data.json")

# Read a JSON file back into a Python dictionary
with open("server_data.json", "r") as f:
    loaded = json.load(f)             # json.load() = "load from file"
    print(loaded["hostname"])         # Output: web-01
```

??? note "Why four different json functions? (json.dumps, json.loads, json.dump, json.load)"
    - `json.dumps()` — dictionary **to** string  (s = string)
    - `json.loads()` — string **to** dictionary  (s = string)
    - `json.dump()`  — dictionary **to** file     (no s)
    - `json.load()`  — file **to** dictionary     (no s)

    Just remember: **s = string** (vs file). The rest follows.

---

## HTTP Requests

You already used `curl` on the command line to check website headers. The `requests` library lets you do the same thing from inside a Python script, so you can automate it — check 100 websites in a loop instead of running curl 100 times.

```python
# http_check.py
import requests    # the library we installed with pip

# === GET REQUEST ===
# Like typing a URL into your browser — you're asking for data
response = requests.get("https://httpbin.org/get")

# The response object contains everything the server sent back
print(response.status_code)    # 200 = success, 404 = not found, 500 = server error
print(type(response.json()))   # dict — the server's JSON response as a Python dict

# === CHECKING SECURITY HEADERS ===
# This is like "curl -I https://example.com" but in Python,
# so we can check headers for many sites at once.

# requests.head() sends a HEAD request (headers only, no page body — faster)
r = requests.head("https://example.com")

# r.headers is a dictionary of all the response headers
# .get(header_name, default) returns the value, or the default if header is missing
print(r.headers.get("X-Frame-Options", "❌ MISSING"))
print(r.headers.get("Strict-Transport-Security", "❌ MISSING"))
```

### Security Headers Checker Script

This is a real security tool. Save as `header_checker.py`:

```python
# header_checker.py — Check HTTP security headers for multiple websites
import requests

# The security headers we care about and why they matter
SECURITY_HEADERS = {
    "X-Frame-Options":          "Prevents clickjacking (attacker embedding your site in iframe)",
    "Strict-Transport-Security":"Forces HTTPS — browser won't allow plain HTTP",
    "Content-Security-Policy":  "Reduces XSS attacks by restricting what scripts can run",
    "X-Content-Type-Options":   "Prevents MIME sniffing attacks",
}

def check_headers(url):
    """Check a URL's security headers. Returns a list of findings."""
    print(f"\n--- Checking: {url} ---")

    try:
        # HEAD request = ask for headers only (no page content)
        # timeout=10 = give up after 10 seconds (don't hang forever)
        r = requests.head(url, timeout=10)
        print(f"    Status: {r.status_code}")

        for header, description in SECURITY_HEADERS.items():
            # SECURITY_HEADERS.items() gives us (key, value) pairs one at a time
            # so "header" = the header name, "description" = why it matters
            value = r.headers.get(header)    # None if missing

            if value:
                print(f"    ✅ {header}: {value}")
            else:
                print(f"    ❌ MISSING: {header}")
                print(f"       Why: {description}")

    except requests.exceptions.ConnectionError:
        print(f"    ❌ Could not connect to {url}")
    except requests.exceptions.Timeout:
        print(f"    ❌ Timed out connecting to {url}")


# Run the check on several websites
sites = [
    "https://www.google.com",
    "https://www.amazon.com",
    "https://example.com",
]

for site in sites:        # loop through each site in our list
    check_headers(site)   # call our function for each one
```

```bash
python3 header_checker.py
```

---

## Key Libraries Reference

| Library | Purpose | How to get it |
|---|---|---|
| `requests` | HTTP calls, API interaction | `pip install requests` |
| `json` | Parse/write JSON data | Built-in (no install needed) |
| `os` | File and system operations | Built-in |
| `subprocess` | Run shell commands from Python | Built-in |
| `hashlib` | Generate file hashes for integrity checks | Built-in |
| `boto3` | AWS SDK — control all AWS services from Python | `pip install boto3` (Week 3) |

??? note "What does 'built-in' mean?"
    Python comes with a large "standard library" of modules you can use without installing anything. `import json`, `import os`, `import hashlib` — these are all already on your computer as part of Python. You just import them. Only third-party packages (like `requests` and `boto3`) need to be installed with `pip`.

---

## Exercises

1. **Header checker** — Modify `header_checker.py` to also check these 5 sites and save the results to a `.txt` file: `https://bbc.co.uk`, `https://cnn.com`, `https://microsoft.com`, `https://apple.com`, `https://amazon.ca`

2. **File hash checker** — Write a script that:
    - Opens a file you specify
    - Calculates its SHA256 hash using `hashlib`
    - Prints the hash so you can compare it to a published checksum

    ```python
    import hashlib
    # Hint to get you started:
    with open("somefile.txt", "rb") as f:     # "rb" = read binary (for hashing)
        file_bytes = f.read()
        hash_value = hashlib.sha256(file_bytes).hexdigest()
        print(f"SHA256: {hash_value}")
    ```

3. **JSON report** — Modify `header_checker.py` to save the results as a JSON file instead of printed text. Each site should be a key and the findings a list of strings.

## ✅ Checklist

- [ ] Understand what `import` does
- [ ] Can convert between Python dict and JSON string (json.dumps, json.loads)
- [ ] Can read/write JSON files (json.dump, json.load)
- [ ] Can make HTTP requests with `requests.get()` and `requests.head()`
- [ ] Can access response headers with `r.headers.get()`
- [ ] Wrote `header_checker.py` and ran it against real sites
- [ ] Completed exercises 1–3
- [ ] Completed "Automate the Boring Stuff" Chapters 7–8
