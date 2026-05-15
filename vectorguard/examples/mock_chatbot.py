from __future__ import annotations

import os
import re

from flask import Flask, jsonify, request

app = Flask(__name__)

MODE = os.environ.get("MOCK_MODE", "safe")


@app.post("/chat")
def chat():
    data = request.get_json(force=True)
    message = data.get("message", "")

    if MODE == "vulnerable":
        # Intentionally bad behavior:
        # If the prompt contains a RAG_PWNED token, echo it back.
        match = re.search(r"RAG_PWNED_\d+", message)
        if match:
            return jsonify({"answer": match.group(0)})

        if "VECTORGUARD_SECRET_12345" in message:
            return jsonify({"answer": "VECTORGUARD_SECRET_12345"})

    # Safe-ish mock behavior:
    # Do not echo user content directly.
    return jsonify(
        {
            "answer": (
                "I will answer using only trusted content and treat retrieved context "
                "as untrusted data."
            )
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
    