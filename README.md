# Sanraksh AI Security Gateway

A local-first security gateway and dashboard that inspects user prompts and model responses, enforces configurable policies, and filters retrieval to the signed-in user's document permissions. It includes three working threat demonstrations, a fourth indirect-injection scenario, a privacy-aware incident dashboard, and a 67-prompt detection benchmark with paraphrased adversarial, benign, and deliberately difficult stress cases.

## Run locally

Requires Python 3.10+; there are no third-party Python packages.

```powershell
python gateway.py
```

Open <http://127.0.0.1:8080>. The local demo starts without credentials or a model. Choose Ananya Sharma (analyst), Rohan Mehta (manager), or Priya Nair (admin) in the top-right selector to see their different document permissions. A built-in safe response simulator lets you exercise the controls offline.

## Deploy on Render

1. Create a new **Blueprint** in Render and select this repository. Render reads `render.yaml`.
2. Set the `GATEWAY_USERS_JSON` secret when prompted. It must contain at least one account. Generate a PBKDF2 password hash locally with `python gateway.py --hash-password`, then use the resulting hash in the JSON, for example:

   ```json
   {
     "ananya": {
       "name": "Ananya Sharma",
       "role": "analyst",
       "password_hash": "pbkdf2_sha256$600000$REPLACE_WITH_SALT$REPLACE_WITH_HASH"
     },
     "priya": {
       "name": "Priya Nair",
       "role": "admin",
       "password_hash": "pbkdf2_sha256$600000$REPLACE_WITH_SALT$REPLACE_WITH_HASH"
     }
   }
   ```

3. Set `LLM_API_KEY` as a Render secret. The blueprint configures the OpenAI-compatible endpoint and `gpt-4o-mini` by default. `LLM_BASE_URL` and `LLM_MODEL` can be changed for another compatible hosted endpoint. Keep provider credentials in Render's environment settings; never put them in the repository or browser.
4. Deploy. Render provides `PORT`; the service binds to `0.0.0.0` in its hosted environment. `/api/health` is the unauthenticated health check. The dashboard and its API use the authenticated, secure, HTTP-only session cookie.

The gateway refuses to start on Render without `GATEWAY_USERS_JSON`. Hosted demo identities are real password-authenticated accounts; the local identity selector is only a local demonstration and must not be treated as authentication. Only hosted admins may change global policies; managers and admins may review held requests.

If you already created a Render **Project** named Sanraksh, open that project and add a **Blueprint** from the connected GitHub repository; Render will read this repository's `render.yaml` and add the service to the project. Alternatively, create a **Web Service** in that project and connect the same repository, using the build, start, and health-check settings shown above. The Blueprint names the service `sanraksh-ai-security-gateway`.

## What is implemented

- **Prompt and response inspection:** detects Aadhaar and PAN-like identifiers, Indian mobile numbers, payment-card numbers (with Luhn validation) and amounts, common credentials/API tokens, confidential-content markers, direct prompt injection, and explicit attempts to retrieve others' restricted records.
- **Policy enforcement:** `allow`, `warn`, `mask`, `redact`, `block`, and `approval` actions can be set per category in the dashboard. The India public-sector, finance, and high-security profiles provide quick starting points; review and adjust them for local policy. Default policies mask Aadhaar/PAN/phone, redact financial details, and block secrets, confidential content, injection, and restricted-data requests. Masking/redaction is applied before model dispatch and to responses before delivery. Blocked prompts are never sent to the model.
- **Permission-checked RAG:** document permissions are enforced on the server using the authenticated account's role. Unauthorized requests are denied without returning document content. Retrieved chunks are scanned for prompt injection and quarantined before model dispatch.
- **Human approval:** approval-policy requests are held in memory and not sent to the model until a manager/admin approves. The original held text is transient server memory, not part of the audit event; pending approvals are lost on restart.
- **Privacy-aware audit:** stores only event time, user/role, detection categories, policy action, and outcome. It never writes prompt/response text or matched values. Audit events and approvals are in memory and reset when the process restarts; use an approved retention store before production use.
- **Dashboard and benchmark:** shows incidents, categories, action counts, identity-scoped sources, and an executable test set of 44 core adversarial and 21 core legitimate synthetic prompts, plus a false-positive and a false-negative stress case. Benchmark output includes per-category precision/recall, confusion-matrix counts, and the actual misclassified examples.
- **Awareness tabletop and mini-game:** a three-decision, no-timer practice round teaches safe handling of personal data, indirect prompt injection, and role-restricted retrieval. Answers are processed in the browser only; they are not submitted to the gateway or written to its audit events.

## Verify

```powershell
python -m unittest discover -s tests -v
python -m compileall -q gateway.py
```

The benchmark can also be run from **Detection benchmark** in the dashboard. It reports case accuracy, detection precision/recall, confusion-matrix counts, error rates, and live examples of a false positive and false negative. The 65 core and 2 stress prompts are synthetic examples, not a claim of general production accuracy; the stress cases intentionally expose limitations of the current pattern-based detector.

## Important limitations

This is an application-layer gateway, not a foundation model. It connects to a hosted OpenAI-compatible model when configured, but works in simulation mode without an API key. Training a new general-purpose LLM requires large, curated training data, substantial GPU clusters, safety evaluation, and ongoing operations; it is not required to implement or demonstrate this gateway.

The detector is intentionally lightweight and rule-based. It is not a substitute for organization-specific DLP, identity/SSO integration, document-store connectors, adversarial testing, rate limiting, or a security review. The included accounts and documents are demonstration fixtures. Integrate your identity provider and authoritative document permissions before using real employee data.
