from orchestrator.github import is_prerelease, looks_like_version, normalize_repo, parse_repo, semver_key, strip_v


def test_tag_helpers():
    assert strip_v("v2.2.0") == "2.2.0"
    assert strip_v("codeql-bundle-v2.27.4") == "2.27.4"
    assert strip_v("release-2.7.0") == "2.7.0"
    assert looks_like_version("v13.7.0") and looks_like_version("1.1.0") and looks_like_version("codeql-bundle-v2.27.4")
    assert not looks_like_version("r1rv86")
    assert is_prerelease("codeql-bundle-v2.6.0-beta.1") and not is_prerelease("v13.7.0")
    assert max(["v9.9.9", "v13.6.0", "v13.10.1"], key=semver_key) == "v13.10.1"


def test_repo_parsing():
    assert normalize_repo("git@github.com:cbomkit/cbomkit-action.git") == "https://github.com/cbomkit/cbomkit-action"
    assert parse_repo("https://github.com/CycloneDX/cdxgen.git") == ("CycloneDX", "cdxgen")
