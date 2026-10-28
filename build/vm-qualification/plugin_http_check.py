#!/usr/bin/python3 -I
"""Lab helper for the G0-H plugin probe (run as root): create a WHM or cPanel session for a lab user,
log in through cpsrvd, and perform the requested requests inside that session the way a browser does.
argv: <whm|cpanel> <user> <JSON list of [method, session-relative path]>
Prints one JSON report: per request status, content type and a bounded body excerpt (parsed when JSON).
The session token and cookies are never printed."""
import http.client
import json
import ssl
import subprocess
import sys
import urllib.parse

PORTS = {"whm": (2087, "whostmgrd"), "cpanel": (2083, "cpaneld")}

def main():
    service, user, requests = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    port, cp_service = PORTS[service]
    created = json.loads(subprocess.run(["/usr/local/cpanel/bin/whmapi1", "--output=json", "create_user_session",
                                         "user=" + user, "service=" + cp_service], capture_output=True, text=True,
                                        check=True).stdout)
    if created.get("metadata", {}).get("result") != 1:
        print(json.dumps({"error": "session not created"}))
        return
    url = urllib.parse.urlsplit(created["data"]["url"])
    prefix = "/" + url.path.split("/")[1]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # cpsrvd's certificate is not what is being tested

    def request(method, path, cookie=""):
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=60)
        conn.request(method, path, body=b"" if method == "POST" else None,
                     headers={"Cookie": cookie} if cookie else {})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response, body

    login, _ = request("GET", url.path + "?" + url.query)
    cookie = "; ".join(v.split(";", 1)[0] for k, v in login.getheaders() if k.lower() == "set-cookie")
    report = {"login_status": login.status, "results": []}
    for method, path in requests:
        absolute = path.startswith("!")
        target = path[1:] if absolute else prefix + path
        response, body = request(method, target, "" if absolute else cookie)
        entry = {"method": method, "path": path, "status": response.status,
                 "content_type": response.getheader("Content-Type", ""),
                 "has_app_div": b'id="ols-cpanel-app"' in body}
        try:
            entry["json"] = json.loads(body)
        except ValueError:
            entry["excerpt"] = body[:4000].decode("utf-8", "replace")
            entry["length"] = len(body)
        report["results"].append(entry)
    print(json.dumps(report))

if __name__ == "__main__":
    main()
