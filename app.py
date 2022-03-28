import functools
import json
import secrets
from urllib.parse import urlparse

import aiohttp
import aiosqlite
from flask import Flask, abort, redirect, render_template, request, url_for

app = Flask(__name__)

@functools.cache
async def get_host_info(HOST: str) -> dict:
	async with aiohttp.ClientSession() as session:
		async with session.get("http://ip-api.com/json/{0}".format(HOST), ssl=False) as resp:
			return json.loads(str(await resp.text()))

async def prepare_access_log(log: dict) -> dict:
	HOST = log.get("host")
	_host_info = await get_host_info(HOST)
	_location = str("{0}, {1}, {2}".format(_host_info.get("city"), _host_info.get("regionName"), _host_info.get("country")))
	_vpn = bool(_host_info.get("proxy", False))
	_isp = _host_info.get("isp")
	log.update(dict(location=_location, vpn=str(_vpn), isp=_isp))
	return log

@app.before_first_request
async def init_database():
	global DATABASE
	DATABASE = await aiosqlite.connect("database.db", check_same_thread=False)
	DATABASE.row_factory = aiosqlite.Row
	await DATABASE.execute("""CREATE TABLE IF NOT EXISTS `loggers` (
			`code` TEXT NOT NULL UNIQUE,
			`redirect` TEXT NOT NULL
		);""")
	await DATABASE.execute("""CREATE TABLE IF NOT EXISTS `access_logs` (
			`code` TEXT NOT NULL,
			`host` TEXT NOT NULL,
			`ua` TEXT NOT NULL
		);""")
	await DATABASE.commit()

@app.route("/")
async def index():
	return render_template("index.html")

@app.route("/<code>", methods=["GET"])
async def log_access(code):
	async with DATABASE.cursor() as cursor:
		await cursor.execute("SELECT redirect FROM `loggers` WHERE code=?", (code,))
		try:
			REDIRECT = dict(await cursor.fetchone()).get("redirect")
		except TypeError:
			REDIRECT = url_for("index")
		host = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.remote_addr
		if "," in host:
			host = host.split(',')[0]
		ua = request.user_agent.string
		await cursor.execute("INSERT INTO `access_logs` (code, host, ua) VALUES (?, ?, ?)", (code, host, ua))
		await DATABASE.commit()
	return redirect(str(REDIRECT))

@app.route("/new", methods=["POST"])
async def new_logger():
	REDIRECT = request.form.get('redirect', False)
	if not REDIRECT:
		abort(400)
	CODE = secrets.token_urlsafe(8)
	async with DATABASE.cursor() as cursor:
		await cursor.execute("INSERT INTO `loggers` (code, redirect) VALUES (?, ?)", (CODE, REDIRECT))
	await DATABASE.commit()
	__base = urlparse(request.base_url)
	return render_template("success.html", LOGGER_URL=str(__base.scheme + "://" + __base.hostname + "/" + CODE), TRACKING_URL=str(__base.scheme + "://" + __base.hostname + "/track/" + CODE))

@app.route("/track/<code>", methods=["GET"])
async def track_access(code):
	async with DATABASE.cursor() as cursor:
		await cursor.execute("SELECT * FROM `access_logs` WHERE code=?", (code,))
		rows = await cursor.fetchall()
	return render_template("track.html", access_logs=[await prepare_access_log(dict(row)) for row in rows])

if __name__ == "__main__":
	app.run(host="0.0.0.0", port=443)
