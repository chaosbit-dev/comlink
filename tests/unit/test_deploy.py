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
            env = job.get("environment")
            name = env.get("name") if isinstance(env, dict) else env
            # github-pages is the one environment allowed: it holds no secrets, and its branch
            # policy is what stops a run from any branch but main deploying Pages.
            assert env is None or name == "github-pages", path.name


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
    assert "--type spdxjson --predicate sbom.spdx.json" in runs
    # v1 provenance, exactly: "slsaprovenance" alone would also match the older predicate type.
    assert "--type slsaprovenance1 --predicate provenance.json" in runs
    # Signed attestations only: BuildKit's own SBOM/provenance are unsigned.
    build_step = next(s for s in _steps(PUBLISH) if "build-push-action" in s.get("uses", ""))
    assert "sbom" not in build_step["with"] and "provenance" not in build_step["with"]


# The publish steps use the same pinned actions as chaosbit-dev/obsidian-git-mcp@0865acf.
PINNED = {
    "docker/login-action": "8aa5831fb8d48d8f76594c7ddde61ae58019f550",
    "sigstore/cosign-installer": "756fe2d284c7292c4e9b62c8a28f1e5629c59532",
    "anchore/sbom-action": "66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c",
}


def test_publish_steps_use_the_pinned_actions() -> None:
    uses = [s["uses"] for s in _steps(PUBLISH) if "uses" in s]
    for action, sha in PINNED.items():
        assert f"{action}@{sha}" in uses, action
    runs = _run_text(PUBLISH)
    assert "go install" not in runs  # no cosign built from source
    assert "docker login" not in runs  # login only through the pinned action


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
