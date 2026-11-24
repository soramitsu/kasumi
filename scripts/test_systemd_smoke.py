import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_systemd_smoke as runner
import systemd_evidence as sd


class SystemdCustody(unittest.TestCase):
    def test_configuration_check_uses_the_delivered_services_own_account(self):
        for role, (binary, account, config) in sd.ROLES.items():
            with self.subTest(role=role):
                self.assertEqual(runner.check_config_command({"setpriv": "/usr/bin/setpriv"}, role),
                                 ["/usr/bin/setpriv", "--reuid", account, "--regid", account,
                                  "--init-groups", "/usr/local/bin/" + binary, "check-config", config])

    def test_service_inventory_checks_exact_unit_names_including_inactive_units(self):
        runner.require_units_absent("example.service enabled enabled\n")
        runner.require_units_absent("  helper.service loaded active running watches kasumid.service\n")
        for listing in ("kasumid.service masked disabled",
                        "  kasumi-authority.service loaded inactive dead Authority",
                        "● kasumid.service loaded failed failed Kasumi"):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                runner.require_units_absent(listing)

    def observations(self):
        role = "data"
        values = dict.fromkeys(sd.PROPERTIES,"")
        values.update(Id="kasumid.service",FragmentPath=str(sd.UNIT_ROOT/"kasumid.service"),User="kasumi",Group="kasumi",
                      Type="exec",MainPID="55",LoadState="loaded",ActiveState="active",SubState="running",NRestarts="0",
                      Result="success",InvocationID="0"*31+"2",ControlGroup="/system.slice/kasumid.service")
        stat = "55 (kasumid) " + " ".join(["S","1","55"]+["0"]*16+["878"])
        sample = {"pid":55,"stat":stat,"exe":sd.program(role),"sha256":"a"*64,
                  "argv":[sd.program(role),"serve",sd.ROLES[role][2]],"account_uid":101,"account_gid":102,
                  "uids":[101]*4,"gids":[102]*4,"cgroups":["0::"+values["ControlGroup"]],
                  "listeners":[7443,7444,7445],"required_ports":[7443,7444,7445]}
        return role,values,sample

    def test_native_pid_voters_and_owned_sockets(self):
        role,values,sample=self.observations()
        self.assertEqual((values["InvocationID"],(55,878)),sd.active(role,values,sample,"a"*64,[7443,7444,7445]))
        for key, v in (("listeners",[7443,7444]),("uids",[0]*4),("sha256","b"*64),("cgroups",["0::/rogue"])):
            with self.subTest(key=key),self.assertRaises(ValueError):
                sd.active(role,values,dict(sample,**{key:v}),"a"*64,[7443,7444,7445])
        for key,v in (("DropInPaths","/evil"),("NRestarts","1"),("MainPID","54")):
            with self.subTest(key=key),self.assertRaises(ValueError):
                sd.active(role,dict(values,**{key:v}),sample,"a"*64,[7443,7444,7445])

    def test_only_pid_one_can_prove_an_original_invocation_deactivated(self):
        inv = "a"*32
        row = {"_PID":"1","UNIT":"kasumid.service","INVOCATION_ID":inv,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"}
        runner.completed(json.dumps(row),"data",inv)
        for key,v in (("_PID","55"),("UNIT","other.service"),("INVOCATION_ID","b"*32),("MESSAGE_ID","other")):
            with self.assertRaises(ValueError):
                runner.completed(json.dumps(dict(row,**{key:v})),"data",inv)

    def test_stop_requires_normal_exit_and_an_empty_original_cgroup(self):
        role,v,sample=self.observations()
        v.update(ActiveState="inactive",SubState="dead",MainPID="0",ExecMainCode="1",ExecMainStatus="0")
        proof={"original_pid":55,"original_birth":878,"observed_stat":None,"processes":[]}
        sd.stopped(role,v,proof,sample)
        for change in ({"observed_stat":sample["stat"]},{"processes":[56]}):
            with self.assertRaises(ValueError):
                sd.stopped(role,v,dict(proof,**change),sample)
        with self.assertRaises(ValueError):
            sd.stopped(role,dict(v,ExecMainCode="2"),proof,sample)

    def test_installer_refuses_existing_name_and_remover_requires_original_inode_and_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);src=root/"source";src.write_bytes(b"[Unit]\n");digest=sd.sha256(src)
            with patch.object(sd,"UNIT_ROOT",root):
                created=sd.install("data",src,digest)
                with self.assertRaises(FileExistsError):sd.install("data",src,digest)
                with self.assertRaises(ValueError):sd.remove("data",dict(created,inode=0))
                self.assertEqual(sd.remove("data",created),{"removed":created})

    def test_protected_client_cannot_authenticate_another_service(self):
        cfg={"admin":{"listen":"127.0.0.1:8444"}}
        client={"resource":{"kind":"control"},"administrative_members":{"1":{"endpoint":"https://localhost:8444","certificate_pins":["a"*64]}}}
        self.assertEqual(runner.trust("data",cfg,client,"a"*64),("localhost",8444))
        with self.assertRaises(ValueError):runner.trust("data",cfg,client,"b"*64)
        with self.assertRaises(ValueError):runner.trust("data",{"admin":{"listen":"127.0.0.1:8445"}},client,"a"*64)
