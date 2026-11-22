"""Guards on the publish workflow: GHCR via GITHUB_TOKEN, no registry credential."""

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
BUILD = (WORKFLOWS / "build-push.yml").read_text()


def _code(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_pushes_to_ghcr_with_github_token() -> None:
    code = _code(BUILD)
    assert "ghcr.io/chaosbit-dev/comlink:main-" in code
    assert "github.token" in code
    assert "registry.home.chaosbit.dev" not in code


def test_no_secrets_or_release_environment() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        code = _code(path.read_text())
        assert "secrets." not in code, path.name
        assert "environment:" not in code, path.name


def test_packages_write_only_on_the_job() -> None:
    code = _code(BUILD)
    top, _, jobs = code.partition("\njobs:")
    assert "packages:" not in top
    assert "packages: write" in jobs


def test_sortable_tag_and_no_latest() -> None:
    code = _code(BUILD)
    assert "main-${{ steps.meta.outputs.sha7 }}-${{ steps.meta.outputs.ts }}" in code
    assert ":latest" not in code


def test_signs_and_attests() -> None:
    code = _code(BUILD)
    assert "id-token: write" in code
    assert "cosign sign" in code
    assert "sbom: true" in code
    assert "provenance: mode=max" in code


def test_does_not_publish_on_pull_requests() -> None:
    on_block = BUILD.split("\njobs:")[0]
    assert "pull_request" not in _code(on_block)


def test_third_party_actions_are_sha_pinned() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for ref in re.findall(r"uses:\s*(\S+@\S+)", path.read_text()):
            assert re.search(r"@[0-9a-f]{40}$", ref), f"{path.name}: {ref}"
