"""
Тестовый backend — имитирует уязвимое веб-приложение.
Используется только для демонстрации работы WAF.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Backend работает. WAF защищает этот сервис."})


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": []})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "ok", "user": data.get("username", "anonymous")})


@app.route("/comment", methods=["POST"])
def comment():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "ok", "comment": data.get("text", "")})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
