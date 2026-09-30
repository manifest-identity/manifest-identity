"""Every refusal a provider parser can make, made once (1.14).

The four parsers of subphase 1.14 state their contract in refusals: a
file that breaks the provider's own rules, one that contradicts
itself, one that is too large or is not the document it claims to be.
The coverage service noticed that most of those branches had no test
behind them, which made them claims. Each refusal below is produced by
one input and checked for the rule it names and for the absence of the
value that tripped it, because a refusal that repeats file content is
the one leak this product forbids at every door.
"""

import json

import pytest

from manifest_identity.observe.providers.active_directory import (
    directory_export as directory,
)
from manifest_identity.observe.providers.azure import tenant_export as azure
from manifest_identity.observe.providers.google_cloud import project_export as google
from manifest_identity.observe.providers.kubernetes import rbac_dump as kubernetes
from manifest_identity.observe.providers.okta import org_export as okta
from tests.test_active_directory_import import GROUP as AD_GROUP
from tests.test_active_directory_import import SID as AD_SID
from tests.test_active_directory_import import USER as AD_USER
from tests.test_active_directory_import import minimal as ad_minimal
from tests.test_azure_import import GUID
from tests.test_azure_import import minimal as azure_minimal
from tests.test_google_cloud_import import minimal as google_minimal
from tests.test_kubernetes_import import binding, dump
from tests.test_okta_import import GROUP, USER
from tests.test_okta_import import minimal as okta_minimal

LONG = "x" * 2000
CONTROL = "bad\x01name"
TOO_MANY = ["x"] * 100_001
NOT_A_TIME = "yesterday-ish"

# Each case: the parser, the bytes, the rule the refusal must name, and
# the values that must not be repeated.

KUBERNETES_CASES = [
    (dump({"kind": "ClusterRole", "metadata": {"name": "bad name"}, "rules": []}),
     "whitespace or a control character", ["bad name"]),
    (dump({"kind": "ClusterRole", "metadata": {"name": "n" * 300}, "rules": []}),
     "longer than", ["n" * 300]),
    (dump({"kind": "ClusterRole", "metadata": {"name": "r", "creationTimestamp": 5}, "rules": []}),
     "must be a string", []),
    (dump({"kind": "ClusterRole", "metadata": {"name": "r", "creationTimestamp": NOT_A_TIME},
           "rules": []}), "not ISO 8601", [NOT_A_TIME]),
    (dump({"kind": "ClusterRole", "metadata": {"name": "r"},
           "rules": [{"resources": ["pods"], "verbs": [1]}]}), "list of strings", []),
    (dump({"kind": "ClusterRole", "metadata": {"name": "r"},
           "rules": [{"resources": TOO_MANY, "verbs": ["get"]}]}), "more than", []),
    (json.dumps({"kind": "List", "items": ["not-an-object"]}).encode(),
     "must be an object", ["not-an-object"]),
    (dump({"kind": "ClusterRole", "rules": []}), "metadata is missing", []),
    (json.dumps({"kind": "List", "items": {}}).encode(), "must be a list", []),
    (json.dumps({"kind": "List", "items": TOO_MANY}).encode(), "more than", []),
    (b"x" * (kubernetes.MAX_FILE_BYTES + 1), "exceeds", []),
    (b"{not json", "not valid JSON", ["not json"]),
    (dump({"kind": "RoleBinding", "metadata": {"name": "b"},
           "roleRef": {"kind": "Role", "name": "r"}, "subjects": []}),
     "must carry a namespace", []),
    (dump(binding("b", "r", role_kind="Thing")), "not Role or ClusterRole", ["Thing"]),
    (dump({"kind": "ServiceAccount", "metadata": {"name": "sa"}}), "must carry a namespace", []),
    (dump(binding("twice", "r"), binding("twice", "r")), "binding name appears twice", []),
    (dump({"kind": "ServiceAccount", "metadata": {"name": "sa", "namespace": "ns"}},
          {"kind": "ServiceAccount", "metadata": {"name": "sa", "namespace": "ns"}}),
     "service account appears twice", []),
]

GOOGLE_KEYS = "ci@acme-prod.iam.gserviceaccount.com"
GOOGLE_CASES = [
    (google_minimal(keys={GOOGLE_KEYS: [{"name": "k", "validAfterTime": 5}]}),
     "must be a string", []),
    (google_minimal(keys={GOOGLE_KEYS: [{"name": "k", "validAfterTime": NOT_A_TIME}]}),
     "not ISO 8601", [NOT_A_TIME]),
    (google_minimal(policy={"bindings": [{"role": LONG, "members": []}]}), "longer than", [LONG]),
    (google_minimal(policy={"bindings": [{"role": CONTROL, "members": []}]}),
     "control character", ["bad\x01name"]),
    (google_minimal(policy={"bindings": {}}), "must be a list", []),
    (google_minimal(policy={"bindings": [{"role": "roles/viewer", "members": TOO_MANY}]}),
     "more than", []),
    (google_minimal(project="x"), "must be an object", []),
    (google_minimal(policy={"bindings": [{"role": "roles/viewer", "members": ["user:no-at"]}]}),
     "must be an address", ["no-at"]),
    (b"x" * (google.MAX_FILE_BYTES + 1), "exceeds", []),
    (b"{not json", "not valid JSON", ["not json"]),
    (b"[]", "must be a JSON object", []),
    (google_minimal(project={"projectId": "acme-prod", "projectNumber": "abc"}),
     "must be digits", ["abc"]),
    (google_minimal(keys=[]), "keyed by account address", []),
    (google_minimal(activity=[]), "keyed by account address", []),
    (google_minimal(service_accounts=[{"email": "no-at", "uniqueId": "7"}]),
     "not an address", ["no-at"]),
    (google_minimal(service_accounts=[{"email": "a@b", "uniqueId": "seven"}]),
     "must be digits", ["seven"]),
    (google_minimal(role_definitions=[{"name": "owner", "includedPermissions": []}]),
     "not a role name", []),
    (google_minimal(role_definitions=[{"name": "roles/x", "includedPermissions": ["nodot"]}]),
     "service.resource.verb", ["nodot"]),
    (google_minimal(service_accounts=[{"email": "a@b", "uniqueId": "1"},
                                      {"email": "c@d", "uniqueId": "1"}]),
     "identifier appears twice", []),
    (google_minimal(role_definitions=[{"name": "roles/x", "includedPermissions": []},
                                      {"name": "roles/x", "includedPermissions": []}]),
     "role definition appears twice", []),
]

AZURE_USER = {"id": GUID.format(2), "userPrincipalName": "alice@acme.test"}
AZURE_CASES = [
    (azure_minimal(users=[{**AZURE_USER, "createdDateTime": 5}]), "must be a string", []),
    (azure_minimal(users=[{**AZURE_USER, "createdDateTime": NOT_A_TIME}]),
     "not ISO 8601", [NOT_A_TIME]),
    (azure_minimal(users=[{**AZURE_USER, "displayName": LONG}]), "longer than", [LONG]),
    (azure_minimal(users=[{**AZURE_USER, "displayName": CONTROL}]),
     "control character", ["bad\x01name"]),
    (azure_minimal(users=[{**AZURE_USER, "accountEnabled": "yes"}]), "true or false", ["yes"]),
    (azure_minimal(groups={}), "must be a list", []),
    (azure_minimal(groups=[{"id": GUID.format(3), "displayName": "g", "members": TOO_MANY}]),
     "more than", []),
    (azure_minimal(tenant="x"), "must be an object", []),
    (azure_minimal(groups=[{"id": GUID.format(3), "displayName": "g",
                            "members": [{"@odata.type": "#microsoft.graph.device",
                                         "id": GUID.format(2)}]}]),
     "not user, group, or servicePrincipal", ["device"]),
    (b"x" * (azure.MAX_FILE_BYTES + 1), "exceeds", []),
    (b"{not json", "not valid JSON", ["not json"]),
    (b"[]", "must be a JSON object", []),
    (azure_minimal(service_principals=[{"id": GUID.format(5), "displayName": "s",
                                        "servicePrincipalType": "Robot"}]),
     "not one the directory defines", ["Robot"]),
    (azure_minimal(subscriptions=[{"id": GUID.format(9), "role_assignments": [
        {"principalId": GUID.format(2), "principalType": "Alien", "roleDefinitionId": "r",
         "roleDefinitionName": "Reader", "scope": "/subscriptions/" + GUID.format(9)}]}]),
     "not one the service defines", ["Alien"]),
    (azure_minimal(role_definitions=[{"name": "d", "roleName": "Deployer",
                                      "permissions": [{"actions": [7]}]}]),
     "must be a string", []),
    (azure_minimal(users=[AZURE_USER, {**AZURE_USER, "userPrincipalName": "twin@acme.test"}]),
     "identifier appears twice", []),
    (azure_minimal(directory_roles=[{"id": GUID.format(6), "roleTemplateId": GUID.format(7),
                                     "displayName": "Global Administrator",
                                     "members": [{"@odata.type": "#microsoft.graph.user",
                                                  "id": GUID.format(8)}]}]),
     "directory role names a member", []),
    (azure_minimal(subscriptions=[{"id": GUID.format(9), "role_assignments": []},
                                  {"id": GUID.format(9), "role_assignments": []}]),
     "subscription appears twice", []),
]

OKTA_USER = {"id": USER, "profile": {"login": "alice@acme.test"}, "status": "ACTIVE"}
OKTA_CASES = [
    (okta_minimal(users=[{**OKTA_USER, "created": 5}]), "must be a string", []),
    (okta_minimal(users=[{**OKTA_USER, "created": NOT_A_TIME}]), "not ISO 8601", [NOT_A_TIME]),
    (okta_minimal(users=[{**OKTA_USER, "profile": {"login": LONG}}]), "longer than", [LONG]),
    (okta_minimal(users=[{**OKTA_USER, "profile": {"login": CONTROL}}]),
     "control character", ["bad\x01name"]),
    (okta_minimal(groups={}), "must be a list", []),
    (okta_minimal(groups=[{"id": GROUP, "profile": {"name": "g"}, "members": TOO_MANY}]),
     "more than", []),
    (okta_minimal(org="x"), "must be an object", []),
    (b"x" * (okta.MAX_FILE_BYTES + 1), "exceeds", []),
    (b"{not json", "not valid JSON", ["not json"]),
    (b"[]", "must be a JSON object", []),
    (okta_minimal(org={"id": "00otest0000000000001", "subdomain": "Bad Sub"}),
     "not a subdomain", ["Bad Sub"]),
    (okta_minimal(custom_roles=[{"id": "cr0test0000000000001", "label": "x",
                                 "permissions": ["users.read"]}]),
     "not written the way the API writes one", []),
    (okta_minimal(users=[OKTA_USER, OKTA_USER]), "user appears twice", []),
    (okta_minimal(groups=[{"id": GROUP, "profile": {"name": "g"}, "members": []},
                          {"id": GROUP, "profile": {"name": "g"}, "members": []}]),
     "group appears twice", []),
    (okta_minimal(role_assignments=[{"id": "ra0test0000000000001", "type": "ORG_ADMIN",
                                     "assignmentType": "USER",
                                     "principal_id": "00unobody00000000001"}]),
     "names a principal the file does not list", ["00unobody"]),
    (okta_minimal(role_assignments=[{"id": "ra0test0000000000001", "type": "CUSTOM",
                                     "assignmentType": "USER", "principal_id": USER,
                                     "role": "cr0ghost000000000001"}],
                  custom_roles=[{"id": "cr0test0000000000001", "label": "x",
                                 "permissions": ["okta.users.read"]}]),
     "names a role the file does not describe", ["ghost"]),
    (okta_minimal(apps=[{"id": "0oatest0000000000001", "label": "Payroll",
                         "assignments": [{"principal_id": "00unobody00000000001"}]}]),
     "app assignment names a principal", ["00unobody"]),
]


@pytest.mark.parametrize(("data", "rule", "leaked"), KUBERNETES_CASES)
def test_the_kubernetes_parser_refuses_and_repeats_nothing(
    data: bytes, rule: str, leaked: list[str]
) -> None:
    with pytest.raises(kubernetes.ParseError) as caught:
        kubernetes.parse_rbac_dump(data)
    assert rule in str(caught.value)
    for value in leaked:
        assert value not in str(caught.value)


@pytest.mark.parametrize(("data", "rule", "leaked"), GOOGLE_CASES)
def test_the_google_cloud_parser_refuses_and_repeats_nothing(
    data: bytes, rule: str, leaked: list[str]
) -> None:
    with pytest.raises(google.ParseError) as caught:
        google.parse_project_export(data)
    assert rule in str(caught.value)
    for value in leaked:
        assert value not in str(caught.value)


@pytest.mark.parametrize(("data", "rule", "leaked"), AZURE_CASES)
def test_the_azure_parser_refuses_and_repeats_nothing(
    data: bytes, rule: str, leaked: list[str]
) -> None:
    with pytest.raises(azure.ParseError) as caught:
        azure.parse_tenant_export(data)
    assert rule in str(caught.value)
    for value in leaked:
        assert value not in str(caught.value)


@pytest.mark.parametrize(("data", "rule", "leaked"), OKTA_CASES)
def test_the_okta_parser_refuses_and_repeats_nothing(
    data: bytes, rule: str, leaked: list[str]
) -> None:
    with pytest.raises(okta.ParseError) as caught:
        okta.parse_org_export(data)
    assert rule in str(caught.value)
    for value in leaked:
        assert value not in str(caught.value)


AD_USER_ROW = {"SID": AD_USER, "SamAccountName": "alice", "DistinguishedName": "CN=alice,DC=x"}
AD_CASES = [
    (ad_minimal(users=[{**AD_USER_ROW, "PasswordLastSet": 5}]), "must be a string", []),
    (ad_minimal(users=[{**AD_USER_ROW, "PasswordLastSet": NOT_A_TIME}]), "not ISO 8601",
     [NOT_A_TIME]),
    (ad_minimal(users=[{**AD_USER_ROW, "SamAccountName": LONG}]), "longer than", [LONG]),
    (ad_minimal(users=[{**AD_USER_ROW, "SamAccountName": CONTROL}]), "control character",
     [CONTROL]),
    (ad_minimal(users=[{**AD_USER_ROW, "Enabled": "yes"}]), "must be true or false", ["yes"]),
    (ad_minimal(users=[{**AD_USER_ROW, "ServicePrincipalNames": [1]}]), "list of strings", []),
    (ad_minimal(users=[{**AD_USER_ROW, "SID": "bogus"}]), "not a security identifier", ["bogus"]),
    (ad_minimal(users={}), "must be a list", []),
    (ad_minimal(users=TOO_MANY), "more than", []),
    (ad_minimal(users=["not-an-object"]), "must be an object", ["not-an-object"]),
    (ad_minimal(domain="x"), "must be an object", []),
    (ad_minimal(domain={"DNSRoot": "Bad Name", "DomainSID": AD_SID}), "not a domain name",
     ["Bad Name"]),
    (ad_minimal(users=[AD_USER_ROW, AD_USER_ROW]), "identifier appears twice", []),
    (ad_minimal(groups=[{"SID": AD_GROUP, "SamAccountName": "g", "DistinguishedName": "CN=g",
                         "Members": ["nope"]}]), "not a security identifier", ["nope"]),
    (ad_minimal(groups=[{"SID": AD_GROUP, "SamAccountName": "g", "DistinguishedName": "CN=g",
                         "GroupCategory": "Social"}]), "GroupCategory is not one", ["Social"]),
    (ad_minimal(trusts=[{"Name": "partner.test", "Direction": "Sideways"}]),
     "Direction is not one", ["Sideways"]),
    (ad_minimal(trusts=[{"Name": "bad name", "Direction": "Inbound"}]), "not a domain name",
     ["bad name"]),
    (b"x" * (directory.MAX_FILE_BYTES + 1), "exceeds", []),
    (b"{not json", "not valid JSON", ["not json"]),
    (b"[]", "must be a JSON object", []),
]


@pytest.mark.parametrize(("data", "rule", "leaked"), AD_CASES)
def test_the_directory_parser_refuses_and_repeats_nothing(
    data: bytes, rule: str, leaked: list[str]
) -> None:
    with pytest.raises(directory.ParseError) as caught:
        directory.parse_domain_export(data)
    assert rule in str(caught.value)
    for value in leaked:
        assert value not in str(caught.value)


def test_a_list_with_no_items_is_an_empty_cluster() -> None:
    parsed = kubernetes.parse_rbac_dump(b'{"kind": "List"}')
    assert (parsed.roles, parsed.bindings, parsed.service_accounts) == ([], [], [])


def test_an_azure_role_definition_with_actions_is_read() -> None:
    """The custom role list is optional and had never been fed to the
    parser by a test; one definition with actions and notActions."""
    parsed = azure.parse_tenant_export(azure_minimal(role_definitions=[{
        "name": "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/"
                + GUID.format(7),
        "roleName": "Deployer", "roleType": "CustomRole",
        "permissions": [{"actions": ["Microsoft.Compute/*/write"],
                         "notActions": ["Microsoft.Compute/virtualMachines/delete"]}],
    }]))
    definition = parsed.role_definitions[0]
    assert definition.id == GUID.format(7)
    assert definition.custom is True
    assert definition.actions == ["Microsoft.Compute/*/write"]
    assert definition.not_actions == ["Microsoft.Compute/virtualMachines/delete"]
