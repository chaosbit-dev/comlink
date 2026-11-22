"""Guards on the publish workflow: GHCR via GITHUB_TOKEN, no registry credential."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
MAIN_ONLY = "github.ref == 'refs/heads/main' && github.event_name != 'pull_request'"


def _load(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((WORKFLOWS / name).read_text())
    return loaded


BUILD = _load("build-push.yml")
JOBS: dict[str, Any] = BUILD["jobs"]
PUBLISH: dict[str, Any] = JOBS["build"]


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = job["steps"]
    return steps


def _run_text(job: dict[str, Any]) -> str:
    return "\n".join(s.get("run", "") for s in _steps(job))


def test_pushes_to_ghcr_with_github_token() -> None:
    text = (WORKFLOWS / "build-push.yml").read_text()
    assert "ghcr.io/chaosbit-dev/comlink:main-" in text
    assert "github.token" in text
    assert "registry.home.chaosbit.dev" not in text


def test_no_secrets_or_release_environment() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        doc = yaml.safe_load(path.read_text())
        assert "secrets." not in str(doc), path.name
        for job in doc["jobs"].values():
            assert "environment" not in job, path.name


def test_packages_write_only_on_the_publish_job() -> None:
    assert "packages" not in BUILD["permissions"]
    assert PUBLISH["permissions"]["packages"] == "write"
    for name, job in JOBS.items():
        if name != "build":
            assert "packages" not in job.get("permissions", {}), name


def test_publishing_job_runs_only_on_main_and_never_on_pull_requests() -> None:
    assert PUBLISH["if"] == MAIN_ONLY
    assert JOBS["check"]["if"] == MAIN_ONLY
    for name, job in JOBS.items():
        if name == "pr-build":
            continue
        assert job["if"] == MAIN_ONLY, name


def test_pr_build_does_not_push_and_has_no_write_scopes() -> None:
    job = JOBS["pr-build"]
    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["permissions"] == {"contents": "read"}
    for step in _steps(job):
        assert step.get("with", {}).get("push") is False or "build-push" not in step.get("uses", "")


def test_build_job_needs_the_check_job() -> None:
    assert "check" in PUBLISH["needs"]
    assert JOBS["check"]["uses"] == "./.github/workflows/ci.yml"


def test_checkout_does_not_persist_credentials() -> None:
    for name in ("build", "pr-build"):
        checkout = _steps(JOBS[name])[0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"]["persist-credentials"] is False


def test_sortable_tag_and_no_latest() -> None:
    text = (WORKFLOWS / "build-push.yml").read_text()
    assert "main-${{ steps.meta.outputs.sha7 }}-${{ steps.meta.outputs.ts }}" in text
    assert ":latest" not in text


def test_signs_and_attests() -> None:
    assert PUBLISH["permissions"]["id-token"] == "write"
    runs = _run_text(PUBLISH)
    assert "cosign sign" in runs
    assert "cosign attest" in runs
    assert "--type spdxjson" in runs
    assert "--type slsaprovenance" in runs


def test_image_source_label() -> None:
    build_step = next(s for s in _steps(PUBLISH) if "build-push-action" in s.get("uses", ""))
    labels = build_step["with"]["labels"]
    assert "org.opencontainers.image.source=https://github.com/chaosbit-dev/comlink" in labels


def test_actions_are_sha_pinned() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        doc = yaml.safe_load(path.read_text())
        for job in doc["jobs"].values():
            uses = [job["uses"]] if "uses" in job else []
            uses += [s["uses"] for s in job.get("steps", []) if "uses" in s]
            for ref in uses:
                if ref.startswith("./"):
                    continue
                assert re.search(r"@[0-9a-f]{40}$", ref), f"{path.name}: {ref}"


def test_dockerfile_bases_pinned_by_digest() -> None:
    froms = re.findall(r"^FROM\s+(\S+)", (ROOT / "Dockerfile").read_text(), re.M)
    assert froms
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), image
