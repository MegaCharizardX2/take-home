"""Exercise only disposable local containers. Pass --browser to include the Chromium UI test."""
import argparse
import base64
from contextlib import ExitStack
import hashlib
import hmac
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


def docker(*args, stdin=None, ok=True):
    proc = subprocess.run(["docker", *args], input=stdin, text=True, capture_output=True, timeout=120)
    if ok and proc.returncode:
        raise AssertionError("Docker " + args[0] + " failed")
    return proc


def private_env(path, values):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        for k, v in values.items():
            out.write(f"{k}={v}\n")


def run(image, browser, mongo_platform):
    label = "tasky-test-" + secrets.token_hex(5)
    db, app = label + "-db", label + "-app"
    db_password, key, user_password = (secrets.token_hex(32) for _ in range(3))
    uri = f"mongodb://tasky:{db_password}@mongo.wiz.internal:27017/?authSource=admin"
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
        p = Path(tmp)
        private_env(p / "db.env", {"MONGO_INITDB_ROOT_USERNAME": "local-admin",
                                   "MONGO_INITDB_ROOT_PASSWORD": secrets.token_hex(32), "APP_DB_PASSWORD": db_password})
        private_env(p / "app.env", {"MONGODB_URI": uri, "SECRET_KEY": key, "GIN_MODE": "release"})
        docker("network", "create", "--internal", label)
        cleanup.callback(docker, "network", "rm", label, ok=False)
        front = label + "-loopback"
        docker("network", "create", front)
        cleanup.callback(docker, "network", "rm", front, ok=False)
        cleanup.callback(docker, "rm", "-fv", db, ok=False)
        if not mongo_platform:
            mongo_platform = docker("version", "--format", "{{.Server.Os}}/{{.Server.Arch}}").stdout.strip()
        assert mongo_platform in ("linux/amd64", "linux/arm64")
        docker("run", "-d", "--platform", mongo_platform, "--name", db, "--network", label, "--network-alias", "mongo.wiz.internal",
               "--env-file", str(p / "db.env"), "mongo:6.0.26@sha256:0a83b2f824b29c94c5284a49b018db2e3166d9879d1edda5cce545d899ef2bbb", "--auth")

        def mongo(script, *, ok=True):
            return docker("exec", "-i", db, "mongosh", "--norc", "--quiet", "--file", "/dev/stdin",
                          stdin=script, ok=ok)

        admin = 'db.getSiblingDB("admin").auth("local-admin",process.env.MONGO_INITDB_ROOT_PASSWORD);\n'
        for _ in range(60):
            # The image starts a temporary mongod while it creates the first user.
            # Wait for its final server before provisioning the app user.
            final_server = docker("exec", db, "cat", "/proc/1/comm", ok=False).stdout.strip() == "mongod"
            if final_server and mongo(admin + 'if(db.version()!=="6.0.26")quit(1);db.getSiblingDB("admin").getUsers();', ok=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError("authenticated MongoDB did not start")
        mongo(admin + 'db.getSiblingDB("admin").createUser({user:"tasky",pwd:process.env.APP_DB_PASSWORD,roles:[{role:"readWrite",db:"go-mongodb"}]});')
        assert mongo('db.getSiblingDB("go-mongodb").todos.findOne();', ok=False).returncode != 0
        cleanup.callback(docker, "rm", "-fv", app, ok=False)
        docker("create", "--platform", "linux/amd64", "--name", app, "--network", front,
               "--read-only", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "-p", "127.0.0.1::8080", "--env-file", str(p / "app.env"), image)
        docker("network", "connect", label, app)
        docker("start", app)
        endpoint = docker("port", app, "8080/tcp").stdout.strip()
        assert endpoint.startswith("127.0.0.1:")
        port = int(endpoint.rsplit(":", 1)[1])

        def request(method, path, status, body=None, cookie=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            headers = {"Content-Type": "application/json"}
            if cookie:
                headers["Cookie"] = "token=" + cookie
            try:
                conn.request(method, path, None if body is None else json.dumps(body), headers)
                resp = conn.getresponse()
                raw = resp.read()
                assert resp.status == status, f"{method} {path} returned {resp.status}, expected {status}"
                assert resp.getheader("Content-Security-Policy", "").startswith("default-src 'self'")
                parsed = json.loads(raw) if raw and resp.getheader("Content-Type", "").startswith("application/json") else raw
                return parsed, resp.getheader("Set-Cookie", "")
            finally:
                conn.close()

        for _ in range(60):
            try:
                request("GET", "/readyz", 200)
                break
            except (OSError, http.client.HTTPException, AssertionError):
                time.sleep(1)
        else:
            raise AssertionError("amd64 web container failed readiness")
        inspect = json.loads(docker("inspect", app).stdout)[0]
        assert inspect["HostConfig"]["ReadonlyRootfs"] and inspect["Config"]["User"] == "10001:10001"
        assert docker("exec", app, "id", "-u").stdout.strip() == "10001"
        def signup(name):
            account = {"username": name, "password": user_password, "email": name + "@example.invalid"}
            record, _ = request("POST", "/signup", 200, account)
            request("POST", "/signup", 400, account)
            logged, header = request("POST", "/login", 200, account)
            assert record["user_id"] == logged["user_id"]
            token = SimpleCookie(header)["token"]
            assert token["httponly"] and token["secure"] and token["samesite"].lower() == "lax"
            return logged["user_id"], token.value

        alice, a = signup("smoke-a")
        bob, b = signup("smoke-b")
        request("POST", "/signup", 400, {"username": "missing", "email": "missing@example.invalid"})
        request("GET", "/todos/" + alice, 400, cookie="malformed")
        # A deliberately invalid fixture has no real user's ID and only targets this local test process.
        b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=")
        message = b64(b'{"alg":"HS256","typ":"JWT"}') + b"." + b64(json.dumps({
            "username": "000000000000000000000000", "exp": int(time.time()) + 60}).encode())
        invalid = (message + b"." + b64(hmac.digest(b"", message, hashlib.sha256))).decode()
        request("GET", "/todos/" + alice, 401, cookie=invalid)
        expired_claims = {"username": alice, "exp": int(time.time()) - 60}
        expired_data = b64(b'{"alg":"HS256","typ":"JWT"}') + b"." + b64(json.dumps(expired_claims).encode())
        expired = (expired_data + b"." + b64(hmac.digest(key.encode(), expired_data, "sha256"))).decode()
        request("GET", "/todo", 303, cookie=expired)
        request("GET", "/todos/" + alice, 401, cookie=expired)
        request("POST", "/login", 200, {"email": "smoke-a@example.invalid", "password": user_password}, expired)
        task = {"name": "synthetic task", "status": "pending"}
        created, _ = request("POST", "/todo/" + alice, 200, task, a)
        tid = created["insertedId"]
        assert len(tid) == 24 and all(c in "0123456789abcdef" for c in tid)
        request("GET", "/todo/" + tid, 401)
        request("GET", "/todo/" + tid, 404, cookie=b)
        request("GET", "/todos/" + alice, 404, cookie=b)
        request("POST", "/todo/" + alice, 404, task, b)
        request("POST", "/todo/" + bob, 404, {**task, "user_id": alice}, b)
        request("PUT", "/todo", 404, {**task, "ID": tid}, b)
        request("DELETE", "/todo/" + bob + "/" + tid, 404, cookie=b)
        request("DELETE", "/todos/" + alice, 404, cookie=b)
        saved, _ = request("GET", "/todos/" + alice, 200, cookie=a)
        assert [x["ID"] for x in saved] == [tid]
        request("PUT", "/todo", 200, {"ID": tid, "name": "edited", "status": "completed"}, a)
        assert request("GET", "/todo/" + tid, 200, cookie=a)[0]["name"] == "edited"
        request("PUT", "/todo", 404, {**task, "ID": "0" * 23 + "1"}, a)
        mongo(admin + 'const x=db.getSiblingDB("go-mongodb").todos.findOne({_id:ObjectId(' + json.dumps(tid) + ')});'
              'if(Object.keys(x).sort().join(",")!=="_id,name,status,userid" || x.userid!==' + json.dumps(alice) +
              ' || x.status!=="completed") quit(1);')
        request("DELETE", "/todo/" + alice + "/" + tid, 200, cookie=a)
        assert request("GET", "/todos/" + alice, 200, cookie=a)[0] == []
        logs = docker("logs", app)
        assert not any(v in logs.stdout + logs.stderr for v in (db_password, key, user_password, a, uri))
        for bad in ("", "short"):
            env = {"MONGODB_URI": uri}
            if bad:
                env["SECRET_KEY"] = bad
            envfile = p / ("bad-" + str(len(bad)))
            private_env(envfile, env)
            r = docker("run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only",
                       "--env-file", str(envfile), image, ok=False)
            assert r.returncode and "32 bytes" in r.stderr and db_password not in r.stderr
        if browser:
            subprocess.run(["node", str(Path(__file__).with_name("browser.cjs")), f"http://127.0.0.1:{port}"], check=True)
        print(f"PASS amd64 read-only UID 10001, MongoDB 6.0.26 ({mongo_platform}) auth, signup/login/CRUD, BSON keys, cross-user denials, invalid sessions, startup guards and log redaction")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="outpost-tasky:app-test")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--mongo-platform", choices=["linux/amd64", "linux/arm64"])
    args = parser.parse_args()
    run(args.image, args.browser, args.mongo_platform)
