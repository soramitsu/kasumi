"""Install and exercise the delivered systemd units on an isolated native Linux host."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if (sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ or (scripts / "__pycache__").exists()
            or (scripts / "__pycache__").is_symlink() or any(p.suffix in {".pyc",".pyo"} or
            (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*"))):
        raise SystemExit("systemd smoke requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import process_ha_topology as topology
import repeatable_assembly as owned
import systemd_evidence as sd
import verify_release_acceptance as acceptance

KIND = "systemd-smoke"
RUNNER = "scripts/run_systemd_smoke.py"
MODULES = ("scripts/systemd_evidence.py",)


def ports(role, config):
    return [int(config[k]["listen"].rsplit(":",1)[-1]) for k in (("mcp","native","admin") if role == "data" else ("native",))]


def trust(role, cfg, client, certificate):
    if role == "data":
        members = list(client["administrative_members"].values())
        require(len(members) == 1 and client["resource"]["kind"] == "control", "data readiness requires its Control profile")
        endpoint = members[0]
        wanted = cfg["admin"]
    else:
        identifier = str(cfg["replication"]["node_id"])
        require(cfg["installation"]["manifest"] == client["manifest"] and cfg["installation"]["partition"] == client["partition"],
                "authority profile selects another installed partition")
        endpoint = client["endpoints"][identifier]
        wanted = cfg["native"]
    addr = urlsplit(endpoint["endpoint"])
    require(addr.scheme == "https" and addr.port == int(wanted["listen"].rsplit(":",1)[-1])
            and endpoint["certificate_pins"] == [certificate], "protected endpoint differs from installed TLS identity")
    return addr.hostname, addr.port


def tls_probe(role, config, profile):
    cfg, client = owned.read(Path(config)), owned.read(Path(profile))
    leaf = topology.certificate(cfg["admin" if role == "data" else "native"]["tls"]["certificate"])["leaf_sha256"]
    host, port = trust(role, cfg, client, leaf)
    context = ssl.create_default_context(cafile=client["server_ca"])
    identity = client["identity"]
    context.load_cert_chain(identity["certificate"], identity["private_key"])
    with socket.create_connection((host,port), timeout=10) as connection, context.wrap_socket(connection,server_hostname=host) as secured:
        digest = hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
        require(digest == leaf, "live endpoint certificate differs from the enrolled leaf")
        return {"leaf_sha256":digest,"host":host,"port":port,"version":secured.version()}


def probe_result(role, config, result):
    if role == "data":
        require(result["ready"] is True and result["lifecycle"] == "serving", "installed data node is not ready")
    else:
        cfg = result["configuration"]
        require(result["kind"] == "configuration" and type(cfg["policy_epoch"]) is int and type(cfg["revision"]) is int
                and cfg["membership"]["voters"] == config["replication"]["initial_voters"]
                and set(map(int,cfg["membership"]["members"])) >= set(cfg["membership"]["voters"]),
                "installed authority did not return the enrolled operational membership")


def package_inputs(package, artifacts, binaries):
    contents = acceptance.archive_inventory(package)
    for role, (binary, _, _) in sd.ROLES.items():
        unit = contents["systemd/" + sd.unit(role)]
        require(unit["sha256"] == artifacts["systemd-" + role] and not unit["executable"]
                and contents["bin/" + binary]["sha256"] == binaries[binary] and contents["bin/" + binary]["executable"],
                "archive unit or service executable differs from the candidate")
    require(contents["bin/kasumictl"]["sha256"] == binaries["kasumictl"] and contents["bin/kasumictl"]["executable"],
            "packaged operator client differs")


def cmd_map(tools, root, plan):
    systemctl = [tools["systemctl"], "--system", "--no-pager"]
    helper = [tools["python"], "-I","-B","-S",str(Path(tools["source"]) / RUNNER),"helper"]
    units = [sd.unit(role) for role in sd.ROLES]
    return {"manager":systemctl,"helper":helper,"units":units,
            "preflight":[*systemctl,"list-unit-files","--no-legend",*units],
            "transient":[*systemctl,"list-units","--all","--no-legend",*units],
            "reload":[*systemctl,"daemon-reload"],
            "lint":[tools["systemd-analyze"],"verify",*[str(sd.UNIT_ROOT / u) for u in units]],
            "configuration-request":str(Path(root) / "configuration.json")}


def manager_command(c, role, op):
    if op == "show":
        return [*c["manager"],"show","--all","--property="+",".join(sd.PROPERTIES), sd.unit(role)]
    return [*c["manager"],op,sd.unit(role)]


def journal_command(tools, role, invocation):
    # SD_MESSAGE_UNIT_SUCCESS, emitted by systemd PID 1 after deactivation.
    return [tools["journalctl"],"--boot","--no-pager","--output=json","_PID=1","UNIT="+sd.unit(role),
            "INVOCATION_ID="+invocation,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"]


def completed(text, role, invocation):
    records = [json.loads(row) for row in text.splitlines()]
    require(len(records) == 1 and records[0].get("_PID") == "1" and records[0].get("UNIT") == sd.unit(role)
            and records[0].get("INVOCATION_ID") == invocation
            and records[0].get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448",
            "PID 1 did not record successful deactivation of that exact service invocation")


def native_command(tools, plan, c, role):
    if role == "data":
        return [tools["kasumictl"],"--profile",plan["data_client"],"ready"]
    return [tools["kasumictl"],"--config",plan["authority_client"],"authority-maintenance",c["configuration-request"]]


def read_tools(run):
    values = {name:str(Path(shutil.which(name, path=run.environment["PATH"]) or "").resolve(strict=True))
              for name in ("systemctl","systemd-analyze","journalctl")}
    paths = {**values, "python":str(Path(sys.executable).resolve(strict=True)), "source":str(run.source),
             "kasumictl":"/usr/local/bin/kasumictl"}
    require(os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
            and (Path("/sys/fs/cgroup") / "cgroup.controllers").is_file(), "qualification requires native Linux systemd PID 1 and cgroup v2")
    return paths


def status_probes(run, role, generation, cfg, client, c, tools, plan, details):
    command = native_command(tools,plan,c,role)
    key = f"{role}-{generation}"
    details["polls"][key] = []
    for i in range(120):
        step = f"{key}-ready-{i:03d}"
        item = owned.run_owned(run.output,step,command,str(run.source),run.environment,60)
        details["polls"][key].append(item["receipt"])
        run.save()
        receipt = owned.read(owned.check_ref(run.output,item["receipt"]))
        if receipt["exit_code"] == 0:
            probe_result(role,cfg,owned.read(owned.check_ref(run.output,item["stdout"])))
            break
        time.sleep(1)
    else:
        raise ValueError("systemd service never reached authenticated readiness: " + key)
    show = sd.properties(run.command(key+"-show",manager_command(c,role,"show"),60).read_text())
    executable = sd.ROLES[role][0]
    proc = owned.read(run.command(key+"-proc",[*c["helper"],"proc",role,show["MainPID"],
            *map(str,ports(role,cfg))],60))
    identity = sd.active(role,show,proc,run.report["binaries"][executable],ports(role,cfg))
    run.command(key+"-tls",[*c["helper"],"tls",role,sd.ROLES[role][2],plan[role+"_client"]],60,
                scenario=("start-"+role) if generation == 1 else "restart")
    return identity,show,proc


def execute(run, pack, units, plan_file):
    target = run.bind()
    require(target in acceptance.LINUX and sys.platform == "linux", "systemd smoke runs on a native Linux candidate host")
    tools = read_tools(run)
    functional = run.evidence / "evidence.json"
    require(owned.sha256(Path(tools["python"])) == owned.read(functional)["python_executable"]["sha256"],
            "systemd probe interpreter differs from the native functional tool")
    details = {"functional_sha256":owned.sha256(functional),"tools":tools,"artifacts":{},"polls":{},"installed":{},"certificates":{}}
    run.report["details"] = details
    plan = owned.read(run.configuration("systemd-plan",plan_file))
    owned.exact(plan,{"schema","data_client","authority_client"},"systemd smoke plan")
    require(plan["schema"] == "kasumi-systemd-smoke-v1","unsupported systemd smoke plan")
    configs, clients = {}, {}
    for role,(exe,_,conf) in sd.ROLES.items():
        configs[role] = owned.read(run.configuration(role+"-config",conf))
        clients[role] = owned.read(run.configuration(role+"-client",plan[role+"_client"]))
        cert = Path(configs[role]["admin" if role == "data" else "native"]["tls"]["certificate"])
        details["certificates"][role] = owned.retain(run.output,cert)
        trust(role,configs[role],clients[role],topology.certificate(cert)["leaf_sha256"])
        require(owned.sha256(Path(sd.program(role))) == run.report["binaries"][exe],
                "installed service executable differs from functional candidate")
    require(owned.sha256(Path(tools["kasumictl"])) == run.report["binaries"]["kasumictl"],"installed operator executable differs")
    details["artifacts"] = {"package:"+target:owned.sha256(pack), **{"systemd-"+k:owned.sha256(v) for k,v in units.items()}}
    package_inputs(pack,details["artifacts"],run.report["binaries"])
    q = run.output / "configuration.json"
    domain_run.durable_json(q,{"kind":"configuration"})
    c = cmd_map(tools,run.output,plan)
    run.save()
    active = set()
    with Path("/run/kasumi-release-systemd-smoke.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ("preflight","transient"):
            require(not run.command(name,c[name],60).read_bytes().strip(),
                    "host already owns or has loaded a service with the published unit name")
        try:
            for role, file in units.items():
                step = "install-"+role
                created = owned.read(run.command(step,[*c["helper"],"install",role,str(file),details["artifacts"]["systemd-"+role]],60,
                                                 scenario="install-units"))
                details["installed"][role] = created
                run.save()
            run.command("analyze",c["lint"],120,scenario="install-units")
            run.command("reload",c["reload"],60,scenario="install-units")
            previous = {}
            for role in sd.ROLES:
                run.command("check-config-"+role,[sd.program(role),"check-config",sd.ROLES[role][2]],180)
                active.add(role)
                run.command("start-"+role,manager_command(c,role,"start"),180)
                previous[role] = status_probes(run,role,1,configs[role],clients[role],c,tools,plan,details)
            for role in sd.ROLES:
                prior,old,proc = previous[role]
                run.command("restart-"+role,manager_command(c,role,"restart"),600)
                current = status_probes(run,role,2,configs[role],clients[role],c,tools,plan,details)
                require(current[0][0] != prior[0] and current[0][1] != prior[1],"restart reused the original invocation")
                displaced = owned.read(run.command("replaced-"+role,[*c["helper"],"gone",str(prior[1][0]),str(prior[1][1]),old["ControlGroup"]],60,scenario="restart"))
                require(current[0][1][0] in displaced["processes"], "replacement is outside the original service cgroup")
                journal = run.command("restart-journal-"+role,journal_command(tools,role,prior[0]),60,scenario="restart")
                completed(journal.read_text(),role,prior[0])
                previous[role] = current
            for role in reversed(sd.ROLES):
                identity,show,proc = previous[role]
                with sd.hold_unit(role):
                    run.command("stop-"+role,manager_command(c,role,"stop"),600)
                    after = sd.properties(run.command("stopped-"+role,manager_command(c,role,"show"),60).read_text())
                dead = owned.read(run.command("drained-"+role,[*c["helper"],"gone",str(identity[1][0]),str(identity[1][1]),show["ControlGroup"]],
                                              60,scenario="clean-stop"))
                sd.stopped(role,after,dead,proc)
                journal = run.command("stop-journal-"+role,journal_command(tools,role,identity[0]),60,scenario="clean-stop")
                completed(journal.read_text(),role,identity[0])
                active.remove(role)
        finally:
            # Stop every start that this attempt requested, even when the named
            # process failed readiness or the manager was interrupted.
            clean = []
            for role in sorted(active):
                try:
                    run.command("cleanup-stop-"+role,manager_command(c,role,"stop"),600)
                except Exception as exc:
                    clean.append(str(exc))
            for role, created in reversed(list(details["installed"].items())):
                try:
                    run.command("unlink-"+role,[*c["helper"],"unlink",role,json.dumps(created,sort_keys=True)],60)
                except Exception as exc:
                    clean.append(str(exc))
            if details["installed"]:
                run.command("reload-clean",c["reload"],60)
            require(not clean,"service cleanup failed: "+repr(clean))
        require(not run.command("postflight",c["preflight"],60).read_bytes().strip(),"temporary units still installed")
    run.passed(details)


def verify_domain(root, domain, files, configs, artifacts, candidates):
    facts = domain_run.verify_run(root,domain,files,configs,KIND,RUNNER,MODULES)
    report,custody = facts["report"],facts["custody"]
    target = report["target"]
    require(target in acceptance.LINUX and not domain["topology"], "systemd smoke requires the native Linux target")
    details,params = report["details"],report["invocation"]["parameters"]
    owned.exact(details,{"functional_sha256","tools","artifacts","polls","installed","certificates"},"original systemd run")
    primary = candidates[target]["primary"]["functional"]
    require(details["functional_sha256"] == primary["sha256"], "systemd smoke consumed another functional candidate")
    python_hash = acceptance.json_reference(root,primary)["python_executable"]["sha256"]
    owned.exact(params,{"package","systemd-data","systemd-authority"},"delivered systemd paths")
    required = {"package:"+target,"systemd-data","systemd-authority"}
    require(domain["artifacts"] == details["artifacts"] ==
            {key:artifacts[key]["file"]["sha256"] for key in required},"systemd artifact substitution")
    pack = acceptance.reference(root,artifacts["package:"+target]["file"])
    package_inputs(pack,details["artifacts"],domain["binaries"])
    retained = {v["id"]:owned.check_ref(custody,v["file"]) for v in report["configurations"]}
    require(set(retained) == {"systemd-plan",*(r+k for r in sd.ROLES for k in ("-config","-client"))},
            "systemd installation inputs differ")
    plan = owned.read(retained["systemd-plan"])
    owned.exact(plan,{"schema","data_client","authority_client"},"systemd smoke plan")
    require(plan["schema"] == "kasumi-systemd-smoke-v1", "systemd plan schema differs")
    tools = details["tools"]
    owned.exact(tools,{"systemctl","systemd-analyze","journalctl","python","source","kasumictl"},"native manager utilities")
    require(tools["source"] == str(Path(report["evidence_root"]) / "source")
            and all(Path(p).is_absolute() for p in tools.values()) and tools["kasumictl"] == "/usr/local/bin/kasumictl"
            and all(tools[k] in {"/usr/bin/"+k,"/bin/"+k} for k in ("systemctl","systemd-analyze","journalctl")),
            "systemd utilities differ")
    c = cmd_map(tools,report["custody_root"],plan)
    steps = iter(report["processes"])
    scenarios = {}
    def raw(name, command, *, scenario=None):
        item = next(steps,None)
        require(item is not None and item["id"] == name,"missing/reordered systemd command "+name)
        original = facts["receipts"][name]
        record = original["record"]
        expected = domain["binaries"].get(Path(command[0]).name)
        if command[0] == tools["python"]:
            expected = python_hash
        output = owned.check_ref(custody,item["log"])
        require(not original["service"] and record["command"] == command and original["exit_code"] == 0
                and record["executable"]["path"] == command[0] and (expected is None or record["executable"]["sha256"] == expected)
                and output == owned.check_ref(custody,record["stdout"]) == custody/name/"stdout.log",
                "systemd control or native command was substituted: "+ name)
        if scenario:
            scenarios.setdefault(scenario,[]).append(name)
        return output.read_text()
    def value(*args,**kwargs):
        return json.loads(raw(*args,**kwargs))
    require(not raw("preflight",c["preflight"]).strip() and not raw("transient",c["transient"]).strip(),
            "the manager had existing installed or transient units")
    require(owned.read(custody / "configuration.json") == {"kind":"configuration"}, "wrong authority maintenance probe")
    require(set(details["installed"]) == set(details["certificates"]) == set(sd.ROLES), "missing installed service")
    for role in sd.ROLES:
        key = "systemd-"+role
        witness = value("install-"+role,[*c["helper"],"install",role,params[key],details["artifacts"][key]],scenario="install-units")
        require(witness == details["installed"][role] and witness["path"] == str(sd.UNIT_ROOT/sd.unit(role))
                and witness["sha256"] == details["artifacts"][key] and isinstance(witness["device"],int)
                and type(witness["inode"]) is int and witness["inode"] > 0,"installation witness differs from delivered unit")
    raw("analyze",c["lint"],scenario="install-units")
    raw("reload",c["reload"],scenario="install-units")
    def generation(role, gen):
        cfg = owned.read(retained[role+"-config"])
        cli = owned.read(retained[role+"-client"])
        pin = topology.certificate(owned.check_ref(custody,details["certificates"][role]))["leaf_sha256"]
        host,port = trust(role,cfg,cli,pin)
        key = f"{role}-{gen}"
        native = native_command(tools,plan,c,role)
        polls = details["polls"][key]
        require(1 <= len(polls) <= 120,"missing authenticated readiness probe")
        for n,item in enumerate(polls):
            p = owned.check_ref(custody,item)
            original = owned.read(p)
            require(p == custody / f"{key}-ready-{n:03d}" / "process.json" and original["command"] == native
                    and original["executable"]["sha256"] == domain["binaries"]["kasumictl"]
                    and (original["exit_code"] == 0) == (n == len(polls)-1), "startup probe substituted or a success skipped")
        probe_result(role,cfg,owned.read(owned.check_ref(custody,original["stdout"])))
        show = sd.properties(raw(key+"-show",manager_command(c,role,"show")))
        proc = value(key+"-proc",[*c["helper"],"proc",role,show["MainPID"],*map(str,ports(role,cfg))])
        identity = sd.active(role,show,proc,domain["binaries"][sd.ROLES[role][0]],ports(role,cfg))
        tls = value(key+"-tls",[*c["helper"],"tls",role,sd.ROLES[role][2],plan[role+"_client"]],
                    scenario="start-"+role if gen == 1 else "restart")
        require(tls["leaf_sha256"] == pin and tls["port"] == port and tls["host"] == host
                and tls["version"] in {"TLSv1.2","TLSv1.3"}, "live TLS endpoint does not match the installed daemon")
        return identity,show,proc
    prev = {}
    for role in sd.ROLES:
        raw("check-config-"+role,[sd.program(role),"check-config",sd.ROLES[role][2]])
        raw("start-"+role,manager_command(c,role,"start"))
        prev[role] = generation(role,1)
    for role in sd.ROLES:
        prior,old,proc = prev[role]
        raw("restart-"+role,manager_command(c,role,"restart"))
        current = generation(role,2)
        require(prior[0] != current[0][0] and prior[1] != current[0][1],"no new systemd invocation or actual process generation")
        gone = value("replaced-"+role,[*c["helper"],"gone",str(prior[1][0]),str(prior[1][1]),old["ControlGroup"]],scenario="restart")
        require((gone["original_pid"],gone["original_birth"]) == prior[1] and gone["cgroup"] == old["ControlGroup"]
                and (gone["observed_stat"] is None or sd.birth(gone["observed_stat"]) != prior[1])
                and current[0][1][0] in gone["processes"], "old daemon survived or replacement is outside its unit")
        completed(raw("restart-journal-"+role,journal_command(tools,role,prior[0]),scenario="restart"),role,prior[0])
        prev[role] = current
    for role in reversed(sd.ROLES):
        identity,show,proc = prev[role]
        raw("stop-"+role,manager_command(c,role,"stop"))
        after = sd.properties(raw("stopped-"+role,manager_command(c,role,"show")))
        dead = value("drained-"+role,[*c["helper"],"gone",str(identity[1][0]),str(identity[1][1]),show["ControlGroup"]],scenario="clean-stop")
        require(dead["cgroup"] == show["ControlGroup"], "checked a different service cgroup after stop")
        sd.stopped(role,after,dead,proc)
        completed(raw("stop-journal-"+role,journal_command(tools,role,identity[0]),scenario="clean-stop"),role,identity[0])
    for role in reversed(sd.ROLES):
        created = details["installed"][role]
        require(value("unlink-"+role,[*c["helper"],"unlink",role,json.dumps(created,sort_keys=True)]) == {"removed":created},
                "temporary unit cleanup omitted or changed an installation")
    raw("reload-clean",c["reload"])
    require(not raw("postflight",c["preflight"]).strip() and next(steps,None) is None
            and set(details["polls"]) == {f"{r}-{i}" for r in sd.ROLES for i in (1,2)}
            and scenarios == {k:[r["step"] for r in v] for k,v in facts["scenarios"].items()},
            "omitted manager operations, stable cleanup or original scenario observations")
    return facts["evidence"]


def helper(args):
    require(sys.platform == "linux" and Path("/proc/1/comm").read_text().strip() == "systemd",
            "native systemd helper needs Linux systemd PID 1")
    op, rest = args[0], args[1:]
    if op == "install":
        result = sd.install(*rest)
    elif op == "unlink":
        role, saved = rest
        result = sd.remove(role,json.loads(saved))
    elif op == "tls":
        result = tls_probe(*rest)
    elif op == "proc":
        role,pid,*ports = rest
        result = sd.kernel(role,int(pid),list(map(int,ports)))
    elif op == "gone":
        pid, born, cgroup = rest
        result = sd.gone(int(pid),int(born),cgroup)
    else:
        raise ValueError("unknown systemd observation")
    print(json.dumps(result,sort_keys=True))


def main():
    if sys.argv[1:2] == ["helper"]:
        helper(sys.argv[2:])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence","journal","output","package","systemd-data","systemd-authority","plan"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--attempt-id",required=True)
    args = parser.parse_args()
    pack = args.package.resolve(strict=True)
    units = {k:getattr(args,"systemd_"+k).resolve(strict=True) for k in sd.ROLES}
    params = {"package":str(pack), **{"systemd-"+k:str(p) for k,p in units.items()}}
    with domain_run.Run(KIND,RUNNER,MODULES,args.evidence,args.output,args.journal,args.attempt_id,
                        params,domain_run.QUALIFYING) as run:
        execute(run,pack,units,args.plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
