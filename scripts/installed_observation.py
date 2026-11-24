"""Check original protected replies and private administrative readbacks."""
import json
from pathlib import Path
import uuid
from urllib.parse import urlsplit

from domain_run import require
import run_observability_probes as probes
import verify_release_acceptance as acceptance


def document(raw):
    return json.loads(raw, object_pairs_hook=probes.unique_json)


def uuid_string(value):
    parsed = uuid.UUID(value)
    require(parsed.int > 0 and str(parsed) == value, "invalid installed operation UUID")
    return value


def coverage(reply, total, tenant):
    coverage = reply["readiness_coverage"]
    epoch = acceptance.check_readiness_epoch(coverage["membership_epoch"])
    require(total >= 129 and coverage["expected_groups"] == coverage["examined_groups"] == total
            and coverage["healthy_groups"] == total and coverage["complete"] is True
            and coverage["fresh"] is True and coverage["detail_limit"] == 128
            and acceptance.check_readiness_epoch(coverage["covered_epoch"]) == epoch
            and acceptance.number(coverage["oldest_probe_age_seconds"], "probe age") < 30
            and reply["lifecycle"] == "serving" and reply["ready"] is True,
            "installed membership has incomplete, unhealthy or expired observation coverage")
    groups = reply["groups"]
    require(len(groups) == len({g["tenant"] for g in groups}) == 128
            and all(g["store_available"] is True and g["quorum"] is True for g in groups),
            "bounded group detail does not reflect the installed healthy groups")
    group, = (g for g in groups if g["tenant"] == tenant)
    require(group["authority_required"] is True and group["routed"] is True
            and acceptance.number(group["authority_remaining_seconds"], "authority lease") > 0,
            "measured data group has no active independent authority lease")
    return epoch


def measurements(reply, metrics, total, tenant):
    epoch = coverage(reply, total, tenant)
    require(probes.gauge(metrics, "ready") == 1 and probes.gauge(metrics, "local_group_details") == 128
            and all(probes.gauge(metrics, "readiness_groups_" + field) == total
                    for field in ("expected", "healthy", "examined")),
            "protected metrics differ from the installed group population")
    for key, value in epoch.items():
        for prefix in ("readiness_epoch_", "readiness_covered_epoch_"):
            require(probes.gauge(metrics, prefix + key) == value, "metric belongs to another membership epoch")
    for disk in ("persistent_disk", "scratch_disk"):
        limits = reply[disk]
        require(0 <= acceptance.uint(limits["charged_bytes"], "disk charge") <= limits["max_bytes"]
                and probes.gauge(metrics, disk + "_max_bytes") == limits["max_bytes"]
                and probes.gauge(metrics, disk + "_charged_bytes") <= limits["max_bytes"],
                "protected capacity exceeds or substitutes the installed disk limit")
    return epoch


def recovery(request, committed, status, projected):
    identifier = uuid_string(request["operation_id"])
    require(committed["request"] == status["request"] == request
            and committed["created_revision"] == status["created_revision"] > 0
            and committed["created_revision"] <= status["updated_revision"]
            and projected == {"operation_id": identifier, "phase": status["phase"],
                "updated_revision": status["updated_revision"], "phase_pending": status["pending_phase"] is not None,
                "terminal": status["phase"] in ("finished", "stopped")},
            "protected recovery response differs from the committed Control operation")


def endpoint(profile, certificates, members, roles):
    bound = profile["administrative_members"]
    require(bool(bound), "administrative profile has no enrolled endpoint")
    for key, peer in bound.items():
        node = members[int(key)]
        digest, port = certificates[node["id"]]
        address = urlsplit(peer["endpoint"])
        require(node["role"] in roles and address.scheme == "https" and address.port == port
                and peer["certificate_pins"] == [digest], "administrative endpoint differs from the measured daemon")
    return sorted(map(int, bound))


def installed_inputs(plan, profiles, configs, nodes, certificates, request):
    acceptance.exact(plan, {"schema", "observer_profile", "operator_profile", "control_profile",
                            "recovery_request", "destination"}, "observability plan")
    require(plan["schema"] == "kasumi-installed-observability-v1" and isinstance(plan["destination"], str)
            and plan["destination"] and all(Path(plan[key]).is_absolute() for key in
                ("observer_profile", "operator_profile", "control_profile", "recovery_request")),
            "unbound installed observability plan")
    members = {node["node_id"]: node for node in nodes}
    observers = endpoint(profiles["observer"], certificates, members, {"data"})
    operators = endpoint(profiles["operator"], certificates, members, {"data"})
    control = endpoint(profiles["control"], certificates, members, {"control"})
    require(len(observers) == 1 and observers == operators and profiles["observer"]["resource"]["kind"] == "control"
            and profiles["control"]["resource"]["kind"] == "control"
            and profiles["operator"]["resource"]["kind"] == "database"
            and set(control) <= {n["node_id"] for n in nodes if n["role"] == "control"},
            "the observed data member or its administrative resource differs")
    data = configs[members[observers[0]]["id"]]
    tenant = profiles["operator"]["tenant"]
    generation, = (t for t in data["tenants"] if t["tenant"] == tenant)
    require(len(data["tenants"]) >= 129 and generation["incarnation"] == profiles["operator"]["resource"]["incarnation"]
            and generation["serving"]["kind"] == "independent" and request["tenant"] == tenant
            and request["source_incarnation"] == generation["incarnation"],
            "operations do not select the same enrolled data tenant")
    uuid_string(request["operation_id"])
    voters = sorted(n["node_id"] for n in nodes if n["role"] == "data")
    require(sorted(data["replication"]["initial_voters"]) == voters and len(voters) == 3,
            "measured node does not use the original three data voters")
    return tenant, voters, len(data["tenants"])
