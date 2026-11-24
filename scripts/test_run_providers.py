import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import provider_artifacts
import run_providers


def tar(entries, mode="w"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755
            if value is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "../elsewhere"
                archive.addfile(info)
            else:
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def image(directory, layers, *, duplicate=False, top_level=False, damage=False):
    entries = {}

    def blob(value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        digest = hashlib.sha256(data).hexdigest()
        entries["blobs/sha256/" + digest] = data
        return {"digest": "sha256:" + digest, "size": len(data)}

    descriptors = [blob(tar(layer, "w:gz")) for layer in layers]
    manifest = blob({"config": blob({"os": "linux", "architecture": "arm64"}), "layers": descriptors})
    manifest["platform"] = {"os": "linux", "architecture": "arm64"}
    index = blob({"manifests": [manifest] * (2 if duplicate else 1)})["digest"][7:]
    if top_level:
        entries["index.json"] = entries.pop("blobs/sha256/" + index)
    if damage:
        key = "blobs/sha256/" + descriptors[0]["digest"][7:]
        entries[key] = bytes(len(entries[key]))
    path = directory / "minio.tar"
    path.write_bytes(tar(entries.items()))
    return path, index


class Providers(unittest.TestCase):
    def test_oci_native_image_layer_replacement_and_whiteouts(self):
        binary = "usr/bin/minio"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, index = image(root, [[(binary, b"one")], [("usr/bin/.wh..wh..opq", b""), (binary, b"two")]],
                                top_level=True)
            self.assertEqual(provider_artifacts.minio(path, "arm64", index), b"two")
            with self.assertRaisesRegex(ValueError, "native image"):
                provider_artifacts.minio(path, "amd64", index)
            with self.assertRaises(ValueError):
                provider_artifacts.minio(path, "arm64")
            for whiteout in (".wh.usr", "usr/.wh.bin", "usr/bin/.wh.minio", "usr/bin/.wh..wh..opq"):
                path, index = image(root, [[(binary, b"one")], [(whiteout, b"")]])
                with self.subTest(whiteout=whiteout), self.assertRaisesRegex(ValueError, "missing"):
                    provider_artifacts.minio(path, "arm64", index)

    def test_oci_rejects_ambiguous_native_target_tampering_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layers = [[("usr/bin/minio", b"official")]]
            for case in ({"damage": True}, {"duplicate": True}):
                path, index = image(root, layers, **case)
                with self.subTest(case=case), self.assertRaises(ValueError):
                    provider_artifacts.minio(path, "arm64", index)
            for change in (("usr/bin", None), ("usr/bin/minio", None), ("../usr/bin/minio", b"other")):
                path, index = image(root, [*layers, [change]])
                with self.subTest(change=change), self.assertRaises(ValueError):
                    provider_artifacts.minio(path, "arm64", index)

    def test_openbao_requires_published_archive_and_exact_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bao.tar.gz"
            path.write_bytes(tar([("./bao", b"real")], "w:gz"))
            key = ("linux", "amd64")
            with self.assertRaisesRegex(ValueError, "checksum|differs"):
                provider_artifacts.openbao(path, key)
            with mock.patch.dict(provider_artifacts.fetch_openbao.DIGESTS, {key: provider_artifacts.sha256(path)}):
                self.assertEqual(provider_artifacts.openbao(path, key), b"real")
            path.write_bytes(tar([("./bao", b"one"), ("bao", b"two")], "w:gz"))
            with mock.patch.dict(provider_artifacts.fetch_openbao.DIGESTS, {key: provider_artifacts.sha256(path)}):
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    provider_artifacts.openbao(path, key)

    def test_commands_require_private_roots_and_loopback(self):
        root = Path("/private/fixture")
        req = {"objects": str(root / "work/scratch/objects"), "certs": str(root / "work/scratch/certs"),
               "port": 16000}
        self.assertIn("127.0.0.1:16000", run_providers.server_command("minio", "/bin/minio", req, root))
        for change in ({"port": True}, {"objects": "/tmp/elsewhere"}, {"args": ["--address", ":80"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                run_providers.server_command("minio", "/bin/minio", {**req, **change}, root)
        with self.assertRaisesRegex(ValueError, "private root"):
            run_providers.server_command("openbao", "/bin/bao", {"config": "/etc/bao.json"}, root)
        with self.assertRaisesRegex(ValueError, "native Linux"):
            run_providers.target_arch("aarch64-apple-darwin")

    def test_openbao_rejects_dev_storage_and_an_unprotected_listener(self):
        path = Path("/private/work/case/bao.json")
        config = {"api_addr": "https://127.0.0.1:6112", "disable_mlock": True,
                  "storage": {"file": {"path": str(path.parent / "bao-storage")}},
                  "listener": [{"tcp": {"address": "127.0.0.1:6112", "tls_cert_file": str(path.parent / "bao.pem"),
                                        "tls_key_file": str(path.parent / "bao.key"), "tls_min_version": "tls13",
                                        "tls_disable_client_certs": True, "cluster_address": "127.0.0.1:0"}}]}
        run_providers.check_bao_listener(config, path)
        for change in ({"api_addr": "http://127.0.0.1:6112"}, {"storage": {"inmem": {}}},
                       {"listener": [{"tcp": {"address": "0.0.0.0:6112", "tls_disable": True}}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                run_providers.check_bao_listener({**config, **change}, path)

    def test_real_runtime_must_configure_both_integrations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            config = {"tenants": [{"keys": {"kind": "transit"}}], "backup_destinations": {"backup": {"kind": "s3"}}}
            path.write_text(json.dumps(config))
            run_providers.check_configuration(path)
            for change in ({"tenants": []}, {"backup_destinations": {}}):
                path.write_text(json.dumps({**config, **change}))
                with self.assertRaisesRegex(ValueError, "Transit key and S3"):
                    run_providers.check_configuration(path)


if __name__ == "__main__":
    unittest.main()
