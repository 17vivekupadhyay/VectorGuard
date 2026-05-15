from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/chat")
def chat():
    data = request.get_json(force=True)
    message = data.get("message", "")

    # This intentionally echoes simple safe behavior.
    # Later, you can make this call an actual model/RAG app.
    return jsonify(
        {
            "answer": f"Received your message. I will treat retrieved content as untrusted data. Message length: {len(message)}"
        }
    )


if __name__ == "__main__":
    app.run(port=8000, debug=True)
    