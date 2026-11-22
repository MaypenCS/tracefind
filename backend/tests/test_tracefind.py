import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from tracefind import breach, probe
from tracefind.sites import Site, load_sites, parse


def mk(name, **kw):
    base = dict(name=name, url=f"https://{name}.test/{{}}", url_main=f"https://{name}.test/", error_type="status_code")
    base.update(kw)
    return Site(**base)


SITES = [
    mk("codes"),                                                     # 200 found / 404 not
    mk("msg", error_type="message", error_msgs=["No such user"]),
    mk("redir", error_type="response_url"),
    mk("strict", regex_check=r"^[a-z]+$"),
    mk("custom", error_codes=[403], probe_url="https://api.custom.test/u/{}"),  # 403 means missing here
    mk("slow"),
    mk("nohead"),
]


def handler(request: httpx.Request):
    host, path = request.url.host, request.url.path
    user = path.rsplit("/", 1)[-1]
    exists = user == "maypen"
    if host == "slow.test":
        raise httpx.ReadTimeout("slow", request=request)
    if host == "nohead.test":
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200 if exists else 404)
    if host == "msg.test":
        return httpx.Response(200, text="profile page" if exists else "Sorry. No such user here")
    if host == "redir.test":
        return httpx.Response(200) if exists else httpx.Response(302, headers={"location": "https://redir.test/"})
    if host == "api.custom.test":
        return httpx.Response(200 if exists else 403)
    return httpx.Response(200 if exists else 404)


def run_search(username):
    async def go():
        return [r async for r in probe.search(username, SITES, transport=httpx.MockTransport(handler))]
    return {r.site: r for r in asyncio.run(go())}


def test_found_user():
    res = run_search("maypen")
    assert {k: v.status for k, v in res.items()} == {
        "codes": "found", "msg": "found", "redir": "found", "strict": "found",
        "custom": "found", "slow": "error", "nohead": "found"}
    assert res["custom"].url == "https://custom.test/maypen"  # shows profile URL, not the probe URL


def test_missing_user_and_regex():
    res = run_search("ghost-99")
    assert res["codes"].status == res["msg"].status == res["redir"].status == "not_found"
    assert res["custom"].status == "not_found"
    assert res["strict"].status == "invalid"


def test_rejects_bad_username():
    with pytest.raises(ValueError):
        run_search("../etc/passwd")


def test_bundled_sites_parse():
    sites = load_sites()
    assert len(sites) > 300
    assert all(not s.nsfw for s in sites)
    assert len(load_sites(include_nsfw=True)) > len(sites)
    assert any(s.name == "GitHub" for s in sites)


def test_parse_skips_junk():
    assert parse({"$schema": "x", "bad": {"nourl": 1}}) == []


def breach_handler(request: httpx.Request):
    if request.url.host == "haveibeenpwned.com":
        if "nobody" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200, json=[
            {"Name": "Old", "Title": "OldSite", "Domain": "old.test", "BreachDate": "2015-01-01",
             "PwnCount": 10, "DataClasses": ["Emails"], "IsVerified": True},
            {"Name": "New", "Title": "NewSite", "Domain": "new.test", "BreachDate": "2024-05-01",
             "PwnCount": 99, "DataClasses": ["Emails", "Passwords"], "IsVerified": True}])
    if request.url.host == "api.dehashed.com":
        assert json.loads(request.content)["query"] == 'email:"me@maypen.ca"'
        return httpx.Response(200, json={"total": 2, "entries": [
            {"id": "1", "email": ["me@maypen.ca"], "password": "hunter2", "database_name": "LeakA"},
            {"id": "2", "email": ["me@maypen.ca"], "username": "me", "database_name": "LeakB"}]})
    return httpx.Response(500)


def test_breach_lookup_summarises_and_redacts(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    monkeypatch.delenv("INTELX_API_KEY", raising=False)
    out = asyncio.run(breach.lookup("me@maypen.ca", transport=httpx.MockTransport(breach_handler)))
    hibp, dh = out
    assert [b["name"] for b in hibp["breaches"]] == ["NewSite", "OldSite"]  # newest first
    assert "hunter2" not in json.dumps(dh)                                  # secrets never returned
    assert dh["breaches"][0] == {"name": "LeakA", "data_types": ["email", "password"], "secrets_exposed": True}
    none = asyncio.run(breach.lookup("nobody@x.test", ["hibp"], transport=httpx.MockTransport(breach_handler)))
    assert none[0]["count"] == 0


def test_hibp_skips_usernames(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    out = asyncio.run(breach.lookup("justauser", ["hibp"], transport=httpx.MockTransport(breach_handler)))
    assert "skipped" in out[0]


def test_api(monkeypatch):
    from tracefind import app as appmod

    async def fake_search(username, sites, **kw):
        for s in sites[:3]:
            yield probe.Result(s.name, s.url.replace("{}", username), "found", 200, 5)

    monkeypatch.setattr(appmod, "search", fake_search)
    c = TestClient(appmod.app)
    assert c.get("/api/health").json()["ok"]
    assert c.get("/api/config").json()["sites"] > 300
    assert c.get("/api/search/stream", params={"username": "bad name"}).status_code == 400
    body = c.get("/api/search/stream", params={"username": "maypen"}).text
    assert body.count("event: result") == 3 and '"found": 3' in body
    for k in ("HIBP_API_KEY", "DEHASHED_API_KEY", "INTELX_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert c.post("/api/breach", json={"term": "a@b.co"}).status_code == 400
