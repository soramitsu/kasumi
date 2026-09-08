#!/usr/bin/env python3
"""Exercise driver failures with synthetic processes; never emit benchmark evidence."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("matrix_driver",SCRIPTS/"run_benchmark_matrix.py")
driver=importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
spec=importlib.util.spec_from_file_location("capacity_report",SCRIPTS/"report_benchmark_capacity.py")
capacity=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


class MatrixFailureTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="kasumi-matrix-test-")
        self.root=Path(self.temporary.name)
        (self.root/"target/release").mkdir(parents=True)
        (self.root/"scripts").mkdir()
        (self.root/"Cargo.toml").write_text("")
        (self.root/"Cargo.lock").write_text("")
        shutil.copyfile(SCRIPTS/"report_benchmark_capacity.py",self.root/"scripts/report_benchmark_capacity.py")
        subprocess.run(["git","init","-q",str(self.root)],check=True)
        code='''import json,sys
from pathlib import Path
args=sys.argv[1:]
def option(name):return args[args.index(name)+1]
mode=option('--modes') if '--modes' in args else 'network'
path=Path(option('--output')) if '--output' in args else Path(option('--output-prefix')+'-1.json')
path.write_text(json.dumps({'format':1,'cases':[],'failures':['synthetic failure'] if mode=='raw' else []}))
raise SystemExit(7 if mode=='raw' else 0)
'''
        for name in ("kasumi-bench","kasumi-bench-loopback","kasumi-bench-network","kasumid"):
            executable=self.root/"target/release"/name
            executable.write_text(f"#!{sys.executable}\n"+code)
            executable.chmod(0o700)
        self.output=self.root/"results"
        self.argv=["driver","--skip-build","--quiet-seconds","0","--documents","1","--tenants","1","--operations","1","--output-directory",str(self.output)]
        self.sample={"unix_seconds":0,"load_average":[0,0,0],"background_cpu_percent":0,"competing_processes":[],"free_disk_bytes":100*2**30,"memory":{}}

    def tearDown(self):
        self.temporary.cleanup()

    def test_failed_case_preserves_exit_hash_and_runs_other_cases(self):
        original_sleep=time.sleep
        with patch.object(driver,"ROOT",self.root),patch.object(sys,"argv",self.argv),patch.object(driver,"host_sample",return_value=self.sample),patch.object(driver.time,"sleep",side_effect=lambda seconds:original_sleep(min(seconds,0.02))):
            with self.assertRaises(SystemExit) as exit:
                driver.main()
        self.assertEqual(exit.exception.code,1)
        result=json.loads((self.output/"matrix.json").read_text())
        self.assertEqual(result["status"],"completed_with_failures")
        self.assertEqual([case["status"] for case in result["cases"]],["failed","passed","passed","passed","passed"])
        self.assertEqual(result["cases"][0]["exit_code"],7)
        self.assertEqual(result["cases"][0]["result_sha256"],driver.digest(self.output/"raw-1.json"))
        self.assertEqual(len(result["failures"]),1)
        self.assertTrue((self.output/"capacity.json").exists())
        report=json.loads((self.output/"capacity.json").read_text())
        self.assertEqual(report["input_matrix_scope"],result["scope"])
        self.assertEqual(report["matrix_sha256"],driver.digest(self.output/"matrix.json"))
        self.assertFalse(report["production_release_acceptance"])
        self.assertIn(result["scope"],(self.output/"capacity.md").read_text())

    def test_low_disk_remains_fatal_when_host_load_is_allowed(self):
        loaded=dict(self.sample,competing_processes=[{"name":"qemu-system-aarch64-headless"}],background_cpu_percent=999,free_disk_bytes=1)
        with patch.object(driver,"ROOT",self.root),patch.object(sys,"argv",self.argv+["--allow-host-load"]),patch.object(driver,"host_sample",return_value=loaded):
            with self.assertRaisesRegex(RuntimeError,"free disk space"):
                driver.main()
        result=json.loads((self.output/"matrix.json").read_text())
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["cases"],[])
        self.assertEqual(result["host_load_violation_counts"],{})

    def test_source_change_still_aborts_before_cases(self):
        calls=0
        def identity():
            nonlocal calls
            calls+=1
            return "initial" if calls<=2 else "changed"
        with patch.object(driver,"ROOT",self.root),patch.object(sys,"argv",self.argv),patch.object(driver,"host_sample",return_value=self.sample),patch.object(driver,"source_identity",side_effect=identity):
            with self.assertRaisesRegex(RuntimeError,"source changed"):
                driver.main()
        result=json.loads((self.output/"matrix.json").read_text())
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["cases"],[])


class CapacityLifecycleTests(unittest.TestCase):
    def test_node_audit_stores_are_distinct_from_raft_groups_and_legacy_results(self):
        with tempfile.TemporaryDirectory(prefix="kasumi-capacity-test-") as temporary:
            directory=Path(temporary)
            (directory/"matrix.json").write_text(json.dumps({"options":{"tenants":"100","documents":1000},"status":"completed"}))
            for mode, count in [("raw",0),("local",1),("replicated",3),("text",1),("network",1)]:
                fixture={"mode":mode,"tenants":100,"documents":1000,"security_audit_stores":count}
                source={"fixture":fixture,"cases":[]} if mode=="network" else {"cases":[fixture]}
                (directory/f"{mode}-100.json").write_text(json.dumps(source))
            rows={row["deployment"]:row for row in capacity.report(directory)["footprints"]}
            for mode, count in [("raw",0),("local",1),("replicated",3),("text",1),("network",1)]:
                self.assertEqual(rows[mode]["service_security_store_count"],count)
                self.assertEqual(rows[mode]["additional_service_security_store"],count>0)
                self.assertEqual(rows[mode]["resident_data_raft_groups"],0 if mode=="raw" else (300 if mode=="replicated" else 100))
                self.assertEqual(rows[mode]["resident_control_raft_groups"],1 if mode=="network" else 0)
            # Retained historical measurements must not acquire costs their
            # original fixture did not include.
            old={"cases":[{"mode":"local","tenants":100,"documents":1000}]}
            (directory/"local-100.json").write_text(json.dumps(old))
            legacy=next(row for row in capacity.report(directory)["footprints"] if row["deployment"]=="local")
            self.assertEqual(legacy["service_security_store_count"],0)

    def test_failed_reopen_preserves_pre_shutdown_observations(self):
        with tempfile.TemporaryDirectory(prefix="kasumi-capacity-test-") as temporary:
            directory=Path(temporary)
            (directory/"matrix.json").write_text(json.dumps({"options":{"tenants":"1","documents":100},"status":"completed_with_failures"}))
            details={"mode":"local","tenants":1,"documents":100,"payload_bytes":102400,"after_workload_rss_bytes":123456,"peak_rss_bytes":234567,"disk_bytes":345678,"shutdown_seconds":0.125}
            source={"cases":[],"progress":[{"mode":"local","tenants":1,"stage":"recovering","details":details,"measurements":[]}],"failures":["synthetic reopen failure"]}
            path=directory/"local-1.json"
            path.write_text(json.dumps(source))
            value=capacity.report(directory)
            row=value["footprints"][0]
            self.assertEqual(row["after_workload_rss_bytes"],123456)
            self.assertEqual(row["process_lifetime_peak_rss_bytes"],234567)
            self.assertEqual(row["disk_file_bytes"],345678)
            self.assertEqual(row["clean_shutdown_seconds"],0.125)
            self.assertIsNone(row["clean_recovery_seconds"])
            self.assertFalse(row["completed_and_identity_verified"])
            self.assertIn("Shutdown s | Recovery s",capacity.markdown(value))
            del details["shutdown_seconds"]
            path.write_text(json.dumps(source))
            self.assertIsNone(capacity.report(directory)["footprints"][0]["clean_shutdown_seconds"])

    def test_network_cleanup_failure_keeps_separate_completed_lifecycle_times(self):
        with tempfile.TemporaryDirectory(prefix="kasumi-capacity-test-") as temporary:
            directory=Path(temporary)
            (directory/"matrix.json").write_text(json.dumps({"options":{"tenants":"1","documents":100},"status":"completed_with_failures"}))
            fixture={"tenants":1,"documents":100,"payload_bytes_each":1024,"phase":"recovered","server_after_workload_rss_bytes":123456,"server_after_recovery_rss_bytes":234567,"server_disk_bytes":345678,"shutdown_seconds":0.125,"recovery_seconds":2.5}
            (directory/"network-1.json").write_text(json.dumps({"cases":[],"fixture":fixture,"fixture_error":"synthetic final cleanup failure"}))
            value=capacity.report(directory)
            row=value["footprints"][0]
            self.assertEqual(row["clean_shutdown_seconds"],0.125)
            self.assertEqual(row["clean_recovery_seconds"],2.5)
            self.assertEqual(row["after_workload_rss_bytes"],123456)
            self.assertEqual(row["after_recovery_rss_bytes"],234567)
            self.assertEqual(row["disk_file_bytes"],345678)
            self.assertIsNone(row["process_lifetime_peak_rss_bytes"])
            self.assertFalse(row["completed_and_identity_verified"])


if __name__ == "__main__":
    unittest.main()
