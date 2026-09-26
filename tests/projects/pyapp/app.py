"""A minimal Flask service, used to measure what docker-trim actually saves."""

from flask import Flask

app = Flask(__name__)


@app.route("/healthz")
def healthz():
    return "ok\n"
