"""Native service-manager observations for the two delivered Kasumi units."""
import hashlib
import os
from pathlib import Path
import pwd
import re

from domain_run import require
from release_gate import sha256

ROLES = {
    "data": ("kasumid", "kasumi", "/var/lib/kasumi/installation/kasumi.json"),
    "authority": ("kasumi-authority", "kasumi-authority", "/var/lib/kasumi-authority/authority.json"),
}
UNIT_ROOT = Path("/run/systemd/system")
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "Type", "User", "Group",
              "MainPID", "ExecMainStatus", "ExecMainCode", "NRestarts", "Result",
              "ControlGroup", "InvocationID", "FragmentPath", "DropInPaths")


def unit(role):
    return ROLES[role][0] + ".service"


def program(role):
    return "/usr/local/bin/" + ROLES[role][0]


def unit_bytes(role, source, expected):
    source = Path(source)
    require(source.is_file() and sha256(source) == expected, "delivered unit bytes changed")
    data = source.read_bytes()
    require(0 < len(data) <= 65536 and hashlib.sha256(data).hexdigest() == expected,
            "unit changed while opening the delivered artifact")
    return data


def install(role, source, expected):
    data = unit_bytes(role, source, expected)
    path = UNIT_ROOT / unit(role)
    # This smoke host owns fresh unit names. An existing administrator's file,
    # including a dangling symlink, must never be replaced or removed.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as out:
        os.fchmod(out.fileno(), 0o644)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
        st = os.fstat(out.fileno())
    return {"path": str(path), "sha256": expected, "device": st.st_dev, "inode": st.st_ino}


def remove(role, created):
    path = UNIT_ROOT / unit(role)
    st = path.lstat()
    require(created == {"path":str(path), "device":st.st_dev, "inode":st.st_ino, "sha256":sha256(path)}
            and path.is_file() and not path.is_symlink(), "temporary unit ownership changed")
    path.unlink()
    return {"removed": created}


def properties(text):
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        require(sep and key not in fields, "invalid systemctl property set")
        fields[key] = value
    require(set(fields) == set(PROPERTIES), "systemctl did not expose every required service property")
    return fields


def kernel(role, pid, ports):
    path = Path("/proc") / str(pid)
    before = (path / "stat").read_text().strip()
    status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines())
    sockets = set()
    for fd in (path / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            sockets.add(target[8:-1])
    listeners = set()
    for family in ("tcp", "tcp6"):
        table = path / "net" / family
        if not table.exists():
            continue
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A" and fields[9] in sockets:
                listeners.add(int(fields[1].rsplit(":", 1)[1], 16))
    exe = path / "exe"
    groups = (path / "cgroup").read_text().splitlines()
    observation = {"pid":pid, "stat":before, "exe":os.readlink(exe), "sha256":sha256(exe),
                   "argv":os.fsdecode((path / "cmdline").read_bytes()).split("\0")[:-1],
                   "uids":list(map(int,status["Uid"].split())), "gids":list(map(int,status["Gid"].split())),
                   "account_uid":pwd.getpwnam(ROLES[role][1]).pw_uid, "account_gid":pwd.getpwnam(ROLES[role][1]).pw_gid,
                   "cgroups":groups, "listeners":sorted(listeners), "required_ports":sorted(ports)}
    after = (path / "stat").read_text().strip()
    require(birth(before) == birth(after), "service process changed during the native sample")
    return observation


def birth(stat):
    fields = stat.rsplit(")", 1)[1].split()
    require(len(fields) > 19 and fields[0] not in ("Z","X","x"), "service is no longer live")
    return int(stat.split(" ",1)[0]), int(fields[19])


def active(role, values, sample, expected_sha, ports):
    name, user, config = ROLES[role]
    require(values["Id"] == unit(role) and values["FragmentPath"] == str(UNIT_ROOT / unit(role))
            and values["DropInPaths"] == "" and values["User"] == values["Group"] == user and values["Type"] == "exec"
            and (values["LoadState"],values["ActiveState"],values["SubState"]) == ("loaded","active","running")
            and values["Result"] == "success" and values["NRestarts"] == "0"
            and re.fullmatch(r"[0-9a-f]{32}",values["InvocationID"]) and int(values["InvocationID"],16) != 0,
            "systemd did not run the original unit without an automatic restart or override")
    pid = int(values["MainPID"])
    require(pid > 1 and sample["pid"] == pid == birth(sample["stat"])[0]
            and sample["exe"] == program(role) and sample["sha256"] == expected_sha
            and sample["argv"] == [program(role),"serve",config]
            and sample["account_uid"] > 0 and sample["account_gid"] > 0
            and sample["uids"] == [sample["account_uid"]]*4 and sample["gids"] == [sample["account_gid"]]*4
            and values["ControlGroup"].endswith("/" + name + ".service")
            and "0::" + values["ControlGroup"] in sample["cgroups"]
            and sample["required_ports"] == sorted(ports) and set(ports) <= set(sample["listeners"]),
            "systemd PID/owner/lifetime, cgroup, executable or enrolled listeners differ")
    return values["InvocationID"], birth(sample["stat"])


def gone(pid, original_birth, cgroup):
    require(re.fullmatch(r"/[a-zA-Z0-9_./@-]+", cgroup) and ".." not in cgroup.split("/"),
            "invalid original process cgroup")
    state = Path("/proc") / str(pid) / "stat"
    try:
        current = state.read_text().strip()
    except FileNotFoundError:
        current = None
    root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    processes = []
    if root.is_dir():
        for roster in root.rglob("cgroup.procs"):
            processes.extend(int(v) for v in roster.read_text().split())
    require(current is None or birth(current) != (pid,original_birth), "original daemon still lives")
    return {"original_pid":pid,"original_birth":original_birth,"observed_stat":current,"cgroup":cgroup,"processes":sorted(set(processes))}


def stopped(role, values, receipt, witness):
    pid, start = birth(witness["stat"])
    require(values["Id"] == unit(role) and values["FragmentPath"] == str(UNIT_ROOT / unit(role))
            and values["ActiveState"] == "inactive" and values["SubState"] == "dead" and values["MainPID"] == "0"
            and values["ExecMainCode"] == "1" and values["ExecMainStatus"] == "0"
            and values["Result"] == "success" and values["NRestarts"] == "0"
            and receipt["original_pid"] == pid and receipt["original_birth"] == start and receipt["processes"] == []
            and (receipt["observed_stat"] is None or birth(receipt["observed_stat"]) != (pid,start)),
            "systemd did not observe ordinary exit and empty ownership after SIGTERM")
