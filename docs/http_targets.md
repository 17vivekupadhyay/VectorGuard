# Custom HTTP Target Configs

VectorGuard can test chatbot and AI application APIs that are not OpenAI-compatible by using a generic HTTP target. Use this when your app exposes an endpoint that accepts prompts or chat messages and returns a JSON response.

## Copy-paste example

```yaml
target:
  type: http
  url: "http://localhost:8000/chat"
  method: POST
  timeout: 90

  headers:
    Content-Type: "application/json"
    Authorization: "Bearer {{env.APP_API_KEY}}"

  body_template:
    message: "{{last_user_message}}"

  response_path: "answer"
```

Do not commit real API keys or tokens. Keep secrets in environment variables, a local `.env` file, or your deployment secret manager, and reference them with placeholders such as `{{env.APP_API_KEY}}`.

## Field reference

- `target.type: http` tells VectorGuard to use the generic HTTP target adapter.
- `url` is the full endpoint URL that VectorGuard sends each test request to.
- `method` is the HTTP verb for the request. Most chatbot APIs use `POST`.
- `headers` is an optional map of request headers, such as `Content-Type` or `Authorization`.
- `body_template` defines the JSON request body sent to your API. Values can include VectorGuard placeholders.
- `response_path` tells VectorGuard where to read the chatbot answer from the JSON response.

For example, this response works with `response_path: "answer"`:

```json
{
  "answer": "Enable MFA from account settings."
}
```

For nested JSON, use dot notation. For example, this response works with `response_path: "data.message"`:

```json
{
  "data": {
    "message": "Enable MFA from account settings."
  }
}
```

## Template placeholders

Use placeholders in `headers` and `body_template` to adapt VectorGuard test prompts to your API shape.

- `{{last_user_message}}` inserts only the latest user message from the test case.
- `{{prompt}}` inserts the full rendered prompt/conversation text.
- `{{messages_json}}` inserts the complete message list as JSON-encoded text.
- `{{env.MY_API_KEY}}` inserts the value of an environment variable, such as `MY_API_KEY`.

Example body using the full prompt:

```yaml
body_template:
  prompt: "{{prompt}}"
```

Example body for APIs that accept a messages payload:

```yaml
body_template:
  messages: "{{messages_json}}"
```

Before running tests, export any environment variables referenced by your config:

```bash
export APP_API_KEY="your_local_test_key"
```

Then run VectorGuard with your HTTP target config:

```bash
python3 -m vectorguard.cli \
  --target path/to/http_target.yaml \
  --tests vectorguard/tests/rag_injection.yaml
```
