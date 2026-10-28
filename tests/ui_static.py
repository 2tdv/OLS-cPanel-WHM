#!/usr/bin/python3
"""Static checks of the WHM and cPanel interfaces (ui/), without Node: the views use exactly the gateway
operations of docs/product-interfaces.md, every operation has a fixture, fixture mode cannot reach a
production build, visible text comes from the one English catalog, controls carry accessible names, and
a built artifact (if present) is complete and free of fixture code. The Node tests: build/ui/test.sh."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
UI = ROOT / "ui"
contract = (ROOT / "docs/product-interfaces.md").read_text()
gateways = contract[contract.index("### Gateways"):]
whm_names = re.findall(r"`(\w+)`", gateways[gateways.index("(names:"):gateways.index(")", gateways.index("(names:"))])
cpanel_names = re.search(r"GET \?api=([a-z_|]+)", gateways[gateways.index("index.live.php"):]).group(1).split("|")
assert {"status", "metrics", "inventory", "compat", "plan", "generations", "doctor", "jobs", "job"} <= set(whm_names), whm_names
actions = set(re.findall(r"\| `(ols\.\w+)` \|", contract)) | set(re.findall(r"`(ols\.\w+)` \(`install", contract))
assert {"ols.plan", "ols.plan_hybrid", "ols.cutover", "ols.apache_return", "ols.rollback", "ols.sync"} <= actions, actions

sources = {p.relative_to(UI).as_posix(): p.read_text() for p in sorted((UI / "src").rglob("*")) if p.suffix in (".vue", ".js")}
code = "\n".join(sources.values())


def used(app):
    # Shared components that read data (the job timeline) belong to the WHM application only.
    text = "\n".join(t for name, t in sources.items() if name.startswith(f"src/{app}/") or (app == "whm" and name.startswith("src/shared/")))
    return set(re.findall(r"use(?:Resource|Paged)\(client, '(\w+)'", text)) | set(re.findall(r"fetchAllPages\(client, '(\w+)'", text))


# Every operation the views read is in the contract and has a fixture; every contract operation is used.
for app, names in (("whm", whm_names), ("cpanel", cpanel_names)):
    reads = used(app)
    assert reads <= set(names), f"{app} reads operations outside the contract: {reads - set(names)}"
    assert set(names) <= reads, f"{app} operations without a view: {set(names) - reads}"
    for name in names:
        json.loads((UI / f"dev/fixtures/{app}/{name}.json").read_text())
json.loads((UI / "dev/fixtures/whm/action.json").read_text())
assert not any("JobTimeline" in t or "useAction" in t for n, t in sources.items() if n.startswith("src/cpanel/")), "cPanel has no actions"
api = sources["src/shared/api.js"]
assert set(re.findall(r"'(ols\.\w+)'", api[api.index("export const ACTIONS"):api.index("})")])) == actions
assert "[REQUEST_HEADER]: '1'" in api and "export const REQUEST_HEADER = 'X-OLS-cPanel-Request'" in api
assert "JSON.stringify({ scope, digest })" in api

# Fixture mode: only through the vite alias, refused by production builds and by the release build script.
assert not re.search(r"""from ['"][./]*dev/|fixtures/""", code), "src imports fixture code"
vite = (UI / "vite.config.js").read_text()
for text in ["if (flag !== fixtures)", "process.env.OLS_UI_OUT", "fixtures ? here('./dev/transport.js') : here('./src/shared/transport.js')",
             "outDir: fixtures ? 'dist-fixtures'"]:
    assert text in vite, text
build = (ROOT / "build/ui/build.sh").read_text()
assert 'OLS_UI_FIXTURES' in build and "node tests/check_dist.mjs /out" in build
assert "OLS_FIXTURE_TRANSPORT" in (UI / "dev/transport.js").read_text()
assert "OLS_FIXTURE_TRANSPORT" in (UI / "tests/check_dist.mjs").read_text()
package = json.loads((UI / "package.json").read_text())
assert package["scripts"]["build"] == "vite build" and "--mode fixtures" in package["scripts"]["build:fixtures"]
assert set(package["dependencies"]) | set(package["devDependencies"]) == {
    "@element-plus/icons-vue", "element-plus", "vue", "vue-i18n", "@vitejs/plugin-vue", "vite"}, "no new npm packages"

# Host pages: unchanged mount points and entries.
assert 'data-endpoint="index.cgi"' in (ROOT / "plugins/whm/index.cgi").read_text()
assert 'data-endpoint="index.live.php"' in (ROOT / "plugins/cpanel/index.live.php").read_text()
assert "{ whm: 'src/whm/main.js', cpanel: 'src/cpanel/main.js' }" in vite

# One route registry per application; no placeholder views (HR-D13).
for app in ("whm", "cpanel"):
    routes = sources[f"src/{app}/routes.js"]
    assert "export const routes = [" in routes and "lazyView(() => import(" in routes
    assert not re.search(r"unavailable|not available|placeholder", routes.split("export const routes")[1], re.I)
assert not (UI / "src/shared/NotAvailable.vue").exists()

# UIX-05: visible text only from the catalog (no literal words in templates or literal labels).
LITERAL_ATTRS = re.compile(r'\s(?:placeholder|title|label|aria-label|alt|description|sub-title|empty-text)="([^"]*[A-Za-z][^"]*)"')
problems = []
for name, text in sources.items():
    if not name.endswith(".vue"):
        continue
    template = text[text.index("<template>"):]
    template = re.sub(r"<!--.*?-->", "", template, flags=re.S)
    for node in re.findall(r">([^<>]+)<", template):
        rest = re.sub(r"\{\{.*?\}\}", "", node, flags=re.S)
        rest = re.sub(r"&\w+;", "", rest)
        if re.search(r"[A-Za-z]", rest):
            problems.append(f"{name}: literal text {rest.strip()!r}")
    for match in LITERAL_ATTRS.finditer(template):
        problems.append(f"{name}: literal attribute {match.group(0).strip()!r}")
assert not problems, "\n".join(problems)
catalog = sources["src/shared/i18n.js"]
assert "locale: 'en'" in catalog and "fallbackLocale: 'en'" in catalog and not re.search(r"\b(fa|ar|de|fr)\s*:\s*\{", catalog)

# UIX-06: every input, select, table and dialog has an accessible name.
for name, text in sources.items():
    for tag in re.findall(r"<el-(?:input|select)\b[^>]*>", text, re.S):
        assert ":id=" in tag or "aria-label" in tag or ' id="' in tag, f"{name}: unlabelled {tag[:60]}"
    for tag in re.findall(r"<el-table\s[^>]*>", text, re.S):
        assert "aria-label" in tag or name == "src/shared/DataTable.vue", f"{name}: table without aria-label"
    for tag in re.findall(r"<el-dialog\b[^>]*>", text, re.S):
        assert ":title=" in tag, f"{name}: dialog without a title"
    for tag in re.findall(r"<el-button\b[^>]*>\s*</el-button>", text, re.S):
        raise AssertionError(f"{name}: button without text")
views = [n for n in sources if "/views/" in n]
assert len(views) >= 9 and all("<PageHeader" in sources[v] for v in views), "every view has a heading"
# Action pages load no data, so they have no loading or empty state (the dashboard's one-click cache clear).
ACTION_VIEWS = {"src/cpanel/views/PurgeNowView.vue"}
assert all("StateView" in sources[v] or "DataTable" in sources[v] or v in ACTION_VIEWS for v in views), "every view has the shared states"
theme = sources["src/shared/theme.css"] if "src/shared/theme.css" in sources else (UI / "src/shared/theme.css").read_text()
assert "prefers-reduced-motion" in theme and ":focus-visible" in theme and ".olsc-app.olsc-dark" in theme

# Customer advisor: optional details, automatic outcomes, and one shared English reason catalog.
advisor = sources["src/cpanel/views/HtaccessView.vue"]
assert "f.outcome === 'translated' ? 'ok' : 'info'" in advisor
assert '<el-collapse class="olsc-gap-below">' in advisor and 'v-model=' not in advisor
assert "HelpTip" not in advisor and "help." not in advisor and "adviceLabel" not in advisor
assert "need attention" not in advisor and "item(s) need attention" not in catalog
reasons = json.loads((UI / "src/shared/i18n.htaccess.en.json").read_text())
assert "reasons: htaccessReasons" in catalog
fixture = json.loads((UI / "dev/fixtures/cpanel/htaccess.json").read_text())
assert {f["outcome"] for f in fixture["files"]} == {"translated", "kept_on_apache"}
for file in fixture["files"]:
    assert file["outcome"] == ("kept_on_apache" if file["blockers"] else "translated")
    assert len(file["reasons"]) == len(file["blockers"])
    for reason, blocker in zip(file["reasons"], file["blockers"]):
        assert reason["directive"] == blocker and reason["reason"] == reasons[reason["reason_key"]]

# A built artifact, when present, has both entries, every referenced file, and no fixture code or data.
dist = ROOT / "artifacts/ui"
manifest_path = dist / ".vite/manifest.json"
checked = "no artifact"
if manifest_path.is_file():
    manifest = json.loads(manifest_path.read_text())
    for entry in ("src/whm/main.js", "src/cpanel/main.js"):
        assert manifest.get(entry, {}).get("isEntry"), entry
    for chunk in manifest.values():
        for file in [chunk["file"], *chunk.get("css", [])]:
            assert (dist / file).is_file(), file
    markers = ["OLS_FIXTURE_TRANSPORT", "fixture-domain.test", "createFixtureSend", "__OLS_FIXTURES__"]
    for path in dist.rglob("*"):
        if path.is_file() and path.suffix in (".js", ".css", ".json"):
            text = path.read_text(errors="replace")
            assert not any(m in text for m in markers), f"fixture code in {path}"
    checked = f"artifact {len(manifest)} manifest entries checked"
print(f"Interface static checks passed ({len(views)} views, {len(whm_names)} WHM and {len(cpanel_names)} cPanel operations, "
      f"{len(actions)} actions; {checked}).")
