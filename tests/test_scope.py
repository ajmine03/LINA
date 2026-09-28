import pytest
from agent.scope import ScopeConfig, extract_host_from_target


def test_extract_host():
    assert extract_host_from_target("https://example.com/test?q=1") == "example.com"
    assert extract_host_from_target("http://192.168.1.10:8080") == "192.168.1.10"
    assert extract_host_from_target("10.0.0.0/24") == "10.0.0.0/24"
    assert extract_host_from_target("sub.target.org") == "sub.target.org"


def test_scope_single_target_ip():
    scope = ScopeConfig.from_single_target("192.168.1.50")
    in_scope, _ = scope.is_in_scope("192.168.1.50")
    assert in_scope is True

    out_scope, _ = scope.is_in_scope("192.168.1.51")
    assert out_scope is False


def test_scope_cidr():
    scope = ScopeConfig(
        name="test_cidr",
        allowed_cidrs=["10.10.0.0/16"]
    )
    assert scope.is_in_scope("10.10.1.20")[0] is True
    assert scope.is_in_scope("10.11.1.20")[0] is False


def test_scope_domains_and_subdomains():
    scope = ScopeConfig(
        name="test_domains",
        allowed_domains=["example.com"],
        allow_subdomains=False
    )
    assert scope.is_in_scope("example.com")[0] is True
    assert scope.is_in_scope("sub.example.com")[0] is False

    scope_with_subs = ScopeConfig(
        name="test_subs",
        allowed_domains=["example.com"],
        allow_subdomains=True
    )
    assert scope_with_subs.is_in_scope("example.com")[0] is True
    assert scope_with_subs.is_in_scope("api.example.com")[0] is True
    assert scope_with_subs.is_in_scope("other.org")[0] is False


def test_disallowed_targets():
    scope = ScopeConfig(
        name="test_disallow",
        allowed_cidrs=["192.168.1.0/24"],
        disallowed_targets=["192.168.1.1"]  # e.g., router gateway disallowed
    )
    assert scope.is_in_scope("192.168.1.10")[0] is True
    assert scope.is_in_scope("192.168.1.1")[0] is False


def test_redirect_validation():
    scope = ScopeConfig(
        name="test_redirect",
        allowed_domains=["app.internal.corp"]
    )
    # Redirect within scope
    valid, _ = scope.validate_redirect("http://app.internal.corp/login", "https://app.internal.corp/dashboard")
    assert valid is True

    # Redirect to external / out-of-scope host
    invalid, reason = scope.validate_redirect("http://app.internal.corp/login", "https://evil-external.com/steal")
    assert invalid is False
    assert "outside authorized scope" in reason
