import json
import secrets
import sqlite3
from urllib.parse import urlparse

import requests
from flask import Flask, abort, redirect, render_template, request, url_for

app = Flask(__name__)

def prepare_access_log(log: dict) -> dict:
    log.update({"vpn": bool(log.get("vpn"))})
    return log

@app.before_first_request
def init_database():
    global DATABASE
    DATABASE = sqlite3.connect("database.db", check_same_thread=False)
    DATABASE.row_factory = sqlite3.Row
    DATABASE.execute("""CREATE TABLE IF NOT EXISTS `loggers` (
            `code` TEXT NOT NULL UNIQUE,
            `redirect` TEXT NOT NULL
        );""")
    DATABASE.execute("""CREATE TABLE IF NOT EXISTS `access_logs` (
            `code` TEXT NOT NULL,
            `host` TEXT NOT NULL,
            `location` TEXT NOT NULL,
            `ua` TEXT NOT NULL,
            `vpn` BOOLEAN NOT NULL
        );""")
    DATABASE.commit()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/<code>", methods=["GET"])
def log_access(code):
    cursor = DATABASE.cursor()
    cursor.execute("SELECT redirect FROM `loggers` WHERE code=?", (code,))
    REDIRECT = dict(cursor.fetchone()).get("redirect") or url_for("index")
    host = request.remote_addr
    ua = request.user_agent.string
    try:
        __host_info = json.loads(str(requests.get("http://ip-api.com/json/{0}?fields=131605".format(host)).text)) or {}
    except:
        __host_info = {}
    location = str("{0}, {1}, {2}".format(__host_info.get("city", "idk the city"), __host_info.get("regionName", "idk the state"), __host_info.get("countryName", "idk the country")))
    vpn = bool(str(__host_info.get("proxy", False)))
    cursor.execute("INSERT INTO `access_logs` (code, host, location, ua, vpn) VALUES (?, ?, ?, ?, ?)", (code, host, location, ua, vpn))
    DATABASE.commit()
    return redirect(str(REDIRECT))

@app.route("/new", methods=["POST"])
def new_logger():
    REDIRECT = request.form.get('redirect', False)
    if not REDIRECT:
        abort(400)
    CODE = secrets.token_urlsafe(8)
    DATABASE.execute("INSERT INTO `loggers` (code, redirect) VALUES (?, ?)", (CODE, REDIRECT))
    DATABASE.commit()
    __base = urlparse(request.base_url)
    return render_template("success.html", LOGGER_URL=str(__base.scheme + "://" + __base.hostname + str(str(":" + str(__base.port)) if __base.port not in [80, 443] else "") + "/" + CODE), TRACKING_URL=str(__base.scheme + "://" + __base.hostname + str(str(":" + str(__base.port)) if __base.port not in [80, 443] else "") + "/track/" + CODE))

@app.route("/track/<code>", methods=["GET"])
def track_access(code):
    cursor = DATABASE.cursor()
    cursor.execute("SELECT * FROM `access_logs` WHERE code=?", (code,))
    rows = cursor.fetchall()
    return render_template("track.html", access_logs=[prepare_access_log(dict(row)) for row in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0")
