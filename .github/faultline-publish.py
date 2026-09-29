"""Trusted workflow delivery; never checks out or executes analyzed source."""
import argparse
import datetime
import hashlib
import html
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request


class PublicationError(Exception):
    """Only fixed, nonsecret operator messages may reach this exception."""


class AmbiguousWrite(PublicationError):
    pass


def require(condition, message="Publication identity or evidence rejected."):
    if not condition:
        raise PublicationError(message)


def text(value, bound=512):
    require(isinstance(value, str) and 0 < len(value) <= bound)
    require(not any(unicodedata.category(c).startswith("C") for c in value))
    return value


def integer(value, minimum=0, maximum=1000):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def pattern(value, expression):
    require(isinstance(value, str) and re.fullmatch(expression, value) is not None)
    return value


def uuid(value):
    return pattern(value, r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def digest(value):
    return pattern(value, r"sha256:[0-9a-f]{64}")


def array(value, bound=1000):
    require(type(value) is list and len(value) <= bound)
    return value


def object_(value):
    require(type(value) is dict)
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key rejected.")
            result[key] = value
        return result
    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), "Nonfinite JSON rejected.")
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_float=finite_float,
            parse_constant=lambda _: require(False, "Nonfinite JSON rejected."))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PublicationError("Malformed or oversized JSON rejected.") from exc


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def origin(value, allow_http):
    text(value, 256)
    pattern(value, r"https?://(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?")
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme in (["https", "http"] if allow_http else ["https"]))
    require(parsed.hostname and parsed.path == "" and not parsed.query and not parsed.fragment)
    require(parsed.username is None and parsed.password is None and parsed.netloc == parsed.netloc.strip())
    try:
        require(parsed.port is None or 1 <= parsed.port <= 65535)
    except ValueError as exc:
        raise PublicationError("Operator origin rejected.") from exc
    return value


def headers(filename):
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_size <= 4096, "Private credential file rejected.")
        raw = stream.read(4097).decode("ascii")
    lines = raw.splitlines()
    require(len(lines) == 1 and re.fullmatch(r"Authorization: Bearer [\x21-\x7e]+", lines[0]),
        "Private credential header rejected.")
    return {"Authorization": lines[0].split(": ", 1)[1]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def request_timeout(*_):
    raise TimeoutError("Bounded request timer expired.")


class HTTP:
    def __init__(self, origins, auth):
        self.origins, self.auth = origins, auth
        self.deadline, self.calls = time.monotonic() + 600, 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, service, route, method="GET", payload=None, cap=8 << 20, binary=False):
        require(route.startswith("/") and not route.startswith("//") and "#" not in route)
        attempts = 2 if method == "GET" else 1
        for attempt in range(attempts):
            remaining = self.deadline - time.monotonic()
            require(remaining > 0 and self.calls < 100, "Publication request budget exhausted.")
            self.calls += 1
            request_headers = {"Accept": "application/json", "User-Agent": "faultline-publication",
                **self.auth.get(service, {})}
            if service == "github":
                request_headers["X-GitHub-Api-Version"] = "2022-11-28"
            data = canonical(payload).encode() if payload is not None else None
            if data is not None:
                require(len(data) <= 16384)
                request_headers["Content-Type"] = "application/json"
            request = urllib.request.Request(self.origins[service] + route, data=data,
                headers=request_headers, method=method)
            previous_handler = signal.signal(signal.SIGALRM, request_timeout)
            signal.setitimer(signal.ITIMER_REAL, min(30, remaining))
            try:
                with self.opener.open(request, timeout=min(30, remaining)) as response:
                    require(response.status == (201 if method == "POST" else 200), "HTTP response rejected.")
                    raw = response.read(cap + 1)
                    require(len(raw) <= cap, "Response exceeds publication cap.")
                    require(time.monotonic() <= self.deadline, "Publication deadline exhausted.")
                return raw if binary else strict_json(raw)
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                if method != "GET":
                    if code >= 500:
                        raise AmbiguousWrite("Publication write unresolved; operator reconciliation required.") from exc
                    raise PublicationError("Publication HTTP write rejected.") from exc
                retry = code == 429 or code >= 500
            except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as exc:
                if method != "GET":
                    raise AmbiguousWrite("Publication write unresolved; operator reconciliation required.") from exc
                retry = True
            except PublicationError as exc:
                if method != "GET":
                    raise AmbiguousWrite("Publication write unresolved; operator reconciliation required.") from exc
                raise
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
            require(retry and attempt + 1 < attempts, "Publication transport rejected or unavailable.")
            require(self.deadline - time.monotonic() > 1, "Publication deadline exhausted.")
            time.sleep(1)

    def inventory(self, route):
        entries = []
        for page in range(1, 6):
            separator = "&" if "?" in route else "?"
            values = array(self.request("github", route + separator + f"per_page=100&page={page}"), 100)
            entries.extend(values)
            if len(values) < 100:
                return entries
        raise PublicationError("Publication inventory incomplete; no creation permitted.")


def load_context(run_id):
    uuid(run_id)
    require(os.environ.get("FAULTLINE_PUBLISH_ISSUES") == "true", "Publication not explicitly enabled.")
    require(os.environ.get("GITHUB_EVENT_NAME") == "pull_request_target")
    repository = pattern(os.environ["FAULTLINE_PUBLISH_REPOSITORY"],
        r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
    repository_id = int(pattern(os.environ["FAULTLINE_PUBLISH_REPOSITORY_ID"], r"[1-9][0-9]{0,18}"))
    require(os.environ["GITHUB_REPOSITORY"] == repository and os.environ["GITHUB_REPOSITORY_ID"] == str(repository_id))
    branch = text(os.environ["FAULTLINE_BASE_BRANCH"], 128)
    harnesses = array(strict_json(os.environ["FAULTLINE_HARNESSES"]), 64)
    require(harnesses and len(set(harnesses)) == len(harnesses))
    for harness in harnesses:
        pattern(harness, r"[A-Za-z0-9_.-]{1,128}")
    project = pattern(os.environ["FAULTLINE_PROJECT"], r"[A-Za-z0-9_.-]{1,128}")
    pipeline = text(os.environ["FAULTLINE_PIPELINE_NAME"], 128)
    version = text(os.environ["FAULTLINE_PIPELINE_VERSION"], 128)
    allow_http = os.environ.get("FAULTLINE_ALLOW_HTTP") == "true"
    origins = {"github": "https://api.github.com", "faultline": origin(os.environ["FAULTLINE_URL"], allow_http),
        "core": origin(os.environ["FAULTLINE_CORE_URL"], allow_http)}
    evidence_origin = origin(os.environ["FAULTLINE_EVIDENCE_URL"], allow_http)
    auth = {"faultline": headers(os.environ["FAULTLINE_HEADERS_FILE"]),
            "github": headers(os.environ["GITHUB_HEADERS_FILE"])}
    event_path = Path(os.environ["GITHUB_EVENT_PATH"])
    require(event_path.stat().st_size <= 1 << 20)
    event = object_(strict_json(event_path.read_bytes()))
    require(event.get("action") in ["opened", "synchronize", "reopened"])
    number = integer(event.get("number"), 1, 2 ** 53 - 1)
    pr = object_(event.get("pull_request"))
    require(pr.get("number") == number and type(pr.get("number")) is int)
    for repo in [event.get("repository"), object_(pr.get("head")).get("repo"), object_(pr.get("base")).get("repo")]:
        repo = object_(repo)
        require(type(repo.get("id")) is int and repo.get("id") == repository_id and repo.get("full_name") == repository)
    require(pr["base"].get("ref") == branch)
    base = pattern(pr["base"].get("sha"), r"[0-9a-f]{40}")
    head = pattern(pr["head"].get("sha"), r"[0-9a-f]{40}")
    http = HTTP(origins, auth)
    run = object_(http.request("faultline", "/v1/runs/" + run_id))
    require(run.get("id") == run_id and run.get("mode") == "harnessed" and run.get("state") == "proven"
        and run.get("error") == "" and run.get("challenge_type") == "delta")
    require(run.get("repo_url") == "https://github.com/" + repository and run.get("project") == project
        and run.get("base_ref") == base and run.get("delta_ref") == head)
    require(run.get("harnesses") == harnesses and run.get("pipeline_name") == pipeline and run.get("pipeline_version") == version)
    faults = integer(run.get("fault_count"), 1)
    integer(run.get("patch_count"))
    ended = text(run.get("ended_at"), 64)
    # Python3.10 accepts numeric UTC offsets, but not the RFC3339 Z suffix.
    numeric_offset = ended[:-1] + "+00:00" if ended.endswith("Z") else ended
    require(datetime.datetime.fromisoformat(numeric_offset).tzinfo is not None)
    identity = {"repository_id": repository_id, "pull_request": number, "base_sha": base, "head_sha": head}
    trigger = object_(run.get("trigger"))
    require(type(trigger.get("schema_version")) is int and trigger.get("schema_version") == 1
        and trigger.get("source") == "github-actions" and trigger.get("repository") == repository
        and trigger.get("base_branch") == branch)
    for key, value in identity.items():
        require(type(trigger.get(key)) is type(value) and trigger.get(key) == value)
    manifest = digest(run.get("manifest_digest"))
    execution_id = uuid(run.get("keystone_execution_id"))
    execution = object_(http.request("core", "/v1/pipeline-executions/" + execution_id))
    require(execution.get("status") == "succeeded")
    steps = [object_(s) for s in array(execution.get("steps"), 64) if object_(s).get("step_name") == "crs-scan"]
    require(len(steps) == 1 and steps[0].get("status") == "succeeded")
    output_id = digest(steps[0].get("output_id"))
    materialization = object_(http.request("core", "/v1/materializations/" + output_id))
    require(materialization.get("output_id") == output_id and materialization.get("status") == "succeeded")
    outputs = {}
    for output in array(materialization.get("outputs"), 1000):
        output = object_(output)
        name = text(output.get("name"))
        require(name not in outputs)
        digest(output.get("artifact_digest"))
        text(output.get("content_type"), 128)
        outputs[name] = output
    lineage = "inputs" in materialization and "binary" in object_(materialization["inputs"])
    if lineage:
        require(materialization["inputs"]["binary"] == manifest)
        blob = http.request("core", "/v1/artifacts/" + manifest + "/blob", binary=True, cap=1 << 20)
        require("sha256:" + hashlib.sha256(blob).hexdigest() == manifest)
    records = object_(http.request("core", "/v1/materializations/" + output_id + "/output-records"))
    record_map = {}
    for record in array(records.get("output_records")):
        record = object_(record)
        record_id = uuid(record.get("id"))
        require(record_id not in record_map)
        record_map[record_id] = record
    findings = object_(http.request("faultline", "/v1/runs/" + run_id + "/findings"))
    require(len(array(findings.get("faults"))) == faults)
    for key, kind in [("faults", "crs_fault"), ("crashes", "crs_crash"), ("patches", "crs_patch")]:
        seen = set()
        for finding in array(findings.get(key)):
            finding = object_(finding)
            record_id = uuid(finding.get("record_id"))
            require(record_id not in seen)
            seen.add(record_id)
            require(finding.get("kind") == kind and record_id in record_map)
            record = record_map[record_id]
            body = {k: v for k, v in finding.items() if k not in ["kind", "record_id"]}
            require(record.get("kind") == kind and canonical(record.get("body")) == canonical(body))
            pattern(body.get("identifier"), kind + r":[0-9a-f]{64}")
    artifacts = object_(http.request("faultline", "/v1/runs/" + run_id + "/artifacts"))
    names = set()
    for artifact in array(artifacts.get("artifacts")):
        name = text(object_(artifact).get("name"))
        require(name not in names)
        names.add(name)
    root = "/repos/" + repository
    gh_repo = object_(http.request("github", root))
    require(type(gh_repo.get("id")) is int and gh_repo.get("id") == repository_id
        and gh_repo.get("full_name") == repository and gh_repo.get("private") is False
        and gh_repo.get("has_issues") is True)
    current = object_(http.request("github", root + "/pulls/" + str(number)))
    require(current.get("state") == "open" and type(current.get("number")) is int and current.get("number") == number)
    for side, sha in [("base", base), ("head", head)]:
        value = object_(current.get(side))
        repo = object_(value.get("repo"))
        require(value.get("sha") == sha and type(repo.get("id")) is int and repo.get("id") == repository_id
            and repo.get("full_name") == repository)
    require(current["base"].get("ref") == branch)
    return {"http": http, "identity": identity, "repository": repository, "root": root, "run": run,
        "findings": findings, "artifacts": names, "outputs": outputs, "lineage": lineage,
        "harnesses": harnesses, "evidence": evidence_origin + "/ui/#/runs/" + run_id}


def finding_groups(context):
    crashes = {}
    for crash in context["findings"]["crashes"]:
        require(crash["identifier"] not in crashes)
        crashes[crash["identifier"]] = crash
    groups, hashed, total_bytes = {}, set(), 0
    for fault in context["findings"]["faults"]:
        details = object_(fault.get("details"))
        crash = crashes.get(details.get("triggered_by"))
        require(crash is not None)
        cd = object_(crash.get("details"))
        payload = pattern(cd.get("id"), r"[0-9a-f]{64}")
        name = "povs/" + payload + ".bin"
        require(cd.get("reproducer") == name and details.get("reproducer") == name and name in context["artifacts"])
        harness = text(details.get("harness"), 128)
        require(harness in context["harnesses"] and harness == cd.get("fuzzer_name")
            and details.get("engine") == cd.get("engine"))
        require(text(cd.get("sanitizer"), 128) in [v.strip() for v in text(details.get("sanitizers"), 256).split(",")])
        if name not in hashed:
            remaining = (16 << 20) - total_bytes
            require(remaining > 0, "Aggregate input publication cap exhausted.")
            raw = context["http"].request("faultline", "/v1/runs/" + context["run"]["id"] +
                "/artifacts/" + urllib.parse.quote(name, safe="/"), binary=True, cap=min(4 << 20, remaining))
            total_bytes += len(raw)
            require(total_bytes <= 16 << 20 and hashlib.sha256(raw).hexdigest() == payload)
            if name in context["outputs"]:
                require(context["outputs"][name]["artifact_digest"] == "sha256:" + payload)
            hashed.add(name)
        token = details.get("token", "")
        require(isinstance(token, str) and len(token) <= 4096)
        identity = {**context["identity"], "harness": harness, "group": token or "unresolved-group"}
        key = hashlib.sha256(canonical(identity).encode()).hexdigest()
        severity = fault.get("severity")
        require(severity in ["critical", "high", "medium", "low", "info"])
        count = integer(details.get("observations"), 1)
        if key not in groups:
            groups[key] = {"key": key, "identity": {**context["identity"], "harness": harness, "group_hash":
                hashlib.sha256((token or "unresolved-group").encode()).hexdigest()},
                "severity": severity, "title": details.get("title"), "location": details.get("location"), "observations": 0}
        group = groups[key]
        group["observations"] += count
        require(group["observations"] <= 1000)
        ranking = ["critical", "high", "medium", "low", "info"]
        if ranking.index(severity) < ranking.index(group["severity"]):
            group["severity"] = severity
    require(0 < len(groups) <= 16)
    return [groups[key] for key in sorted(groups)]


def public_text(value, limit):
    result = ""
    for char in " ".join(text(value, 4096).split()):
        escaped = re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", html.escape(char).replace("@", "&#64;"))
        if len(result) + len(escaped) > limit:
            break
        result += escaped
    return result


def marker(kind, key):
    return f"<!-- faultline:v1:{kind}:{key} -->"


def identity_line(identity):
    return "Faultline identity: `" + canonical(identity) + "`"


def owned_match(values, mark, identity):
    matches = []
    for value in values:
        value = object_(value)
        body = value.get("body")
        if isinstance(body, str) and mark in body:
            user = object_(value.get("user"))
            require(user.get("login") == "github-actions[bot]" and user.get("type") == "Bot"
                and type(user.get("id")) is int and user["id"] > 0
                and mark in body.splitlines() and identity_line(identity) in body.splitlines(),
                "Foreign publication marker or identity conflict.")
            matches.append(value)
    require(len(matches) <= 1, "Duplicate publication markers require operator reconciliation.")
    return matches[0] if matches else None


def upsert(context, kind, route, mark, identity, payload):
    http = context["http"]
    def find():
        values = http.inventory(route)
        if kind == "issue":
            values = [value for value in values if "pull_request" not in object_(value)]
        return owned_match(values, mark, identity)
    existing = find()
    if existing:
        field = "number" if kind == "issue" else "id"
        number = integer(existing.get(field), 1, 2 ** 53 - 1)
        if existing.get("body") == payload["body"] and (kind != "issue" or existing.get("title") == payload["title"]):
            return existing
        update_route = context["root"] + ("/issues/" if kind == "issue" else "/issues/comments/") + str(number)
    else:
        update_route = route.split("?", 1)[0]
    try:
        value = http.request("github", update_route, "PATCH" if existing else "POST", payload)
        try:
            value = object_(value)
            require(owned_match([value], mark, identity) is not None and value.get("body") == payload["body"]
                and (kind != "issue" or value.get("title") == payload["title"]))
        except PublicationError as exc:
            raise AmbiguousWrite("Publication response identity unresolved.") from exc
        return value
    except AmbiguousWrite:
        reconciled = find()
        require(reconciled is not None and reconciled.get("body") == payload["body"]
            and (kind != "issue" or reconciled.get("title") == payload["title"]),
            "Publication write unresolved; operator reconciliation required.")
        return reconciled


def publish_issues(context):
    groups = finding_groups(context)
    prepared = []
    for group in groups:
        mark = marker("issue", group["key"])
        identity = group["identity"]
        body = (f"{mark}\n{identity_line(identity)}\n\n"
            f"Severity: {group['severity']}. Reported location: {public_text(group['location'], 256)}.\n\n"
            f"Reported group observations: {group['observations']} (not a unique-root-cause count).\n\n"
            f"Analyzed PR: https://github.com/{context['repository']}/pull/{identity['pull_request']}\n\n"
            f"Exact base: `{identity['base_sha']}`\n\nExact head: `{identity['head_sha']}`\n\n"
            f"[Protected Faultline evidence]({context['evidence']})\n\n"
            "Verification scope: CRS-reported crash with own published input evidence; no independent replay is reported by this run.\n\n"
            "This reported group is deduplicated for this exact analyzed commit pair; a later revision may receive another issue. "
            "Cross-revision root-cause identity is not established.\n\n"
            "Creating this issue does not clear the vulnerable-pair check. No issue is automatically closed.")
        if not context["lineage"]:
            body += "\n\nSource pins recorded by Faultline; Core input lineage unavailable."
        require(len(body.encode()) <= 8192)
        title = "Faultline: " + public_text(group["title"], 140)
        require(len(title) <= 160)
        prepared.append((mark, identity, {"title": title, "body": body}))
    links = []
    for mark, identity, payload in prepared:
        value = upsert(context, "issue", context["root"] + "/issues?state=all", mark, identity,
            payload)
        number = integer(value.get("number"), 1, 2 ** 53 - 1)
        links.append(number)
    identity = context["identity"]
    key = hashlib.sha256(canonical(identity).encode()).hexdigest()
    body = (marker("comment", key) + "\n" + identity_line(identity) + "\n\n"
        + "Faultline reported finding groups for this exact pair: "
        + ", ".join(f"[Issue {n}](https://github.com/{context['repository']}/issues/{n})" for n in links)
        + f". [Protected run evidence]({context['evidence']}).\n\n"
        + "The vulnerable-pair scan remains failed. These are reported groups, not an independent safety verdict.")
    require(len(body.encode()) <= 8192)
    upsert(context, "comment", context["root"] + "/issues/" + str(identity["pull_request"]) + "/comments",
        marker("comment", key), identity, {"body": body})
    return links


def append_safe(filename, value):
    require(len(value.encode()) <= 16384)
    fd = os.open(filename, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "w") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        stream.write(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["issues", "repair"])
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        require(args.mode == "issues", "Repair publication is not implemented in this release.")
        require(hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM"),
            "Runner requires Unix absolute request deadline support.")
        # Headers are supplied through private files, never raw token environment.
        for name in ["GITHUB_TOKEN", "GH_TOKEN", "FAULTLINE_TOKEN"]:
            os.environ.pop(name, None)
        context = load_context(args.run_id)
        issues = publish_issues(context)
        append_safe(os.environ["GITHUB_OUTPUT"], f"issue_result=confirmed\nissue_count={len(issues)}\n")
        append_safe(os.environ["GITHUB_STEP_SUMMARY"], f"Faultline issue publication confirmed: {len(issues)} reported groups.\n\n"
            f"[Protected run]({context['evidence']}). Vulnerable-pair scan remains failed.\n\n"
            "Publication is exact-pair deduplicated, not exactly-once across unresolved ambiguous writes. "
            "Operator reconciliation is required before retrying unresolved writes. "
            "Native concurrency may cancel an older queued publication; not every proven run is guaranteed publication.\n")
        print(f"Faultline issue publication confirmed: {len(issues)} reported groups.")
        return 0
    except (PublicationError, KeyError, OSError, ValueError, TypeError) as exc:
        message = str(exc) if isinstance(exc, PublicationError) else "Publication configuration or response unavailable."
        print(message, file=sys.stderr)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            try:
                append_safe(os.environ["GITHUB_STEP_SUMMARY"], "Faultline publication unavailable or unresolved; scan verdict unchanged. "
                    "Operator reconciliation is required before retrying an ambiguous write.\n")
            except (PublicationError, OSError):
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
