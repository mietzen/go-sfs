# pylint: disable=missing-function-docstring, missing-class-docstring, missing-module-docstring

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from time import sleep

import requests
from argon2 import PasswordHasher


def create_testfile(suffix='', content="", directory=None):
    filepath = Path(f'test_file_{suffix}')
    if directory:
        directory.mkdir(parents=True, exist_ok=True)
        filepath = directory.joinpath(filepath)
    with open(filepath, "w", encoding='utf-8') as fid:
        fid.write(content)
    return Path(filepath)


def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def verify_go_argon2_pw(go_argon2, password):
    def argon2_hex_to_b64(hex_string):
        return (
            base64.encodebytes(bytes.fromhex(hex_string))
            .decode("utf-8")
            .strip()
            .replace("=", "")
        )

    argon2_split = go_argon2.split("$")[1:]

    parameter = {
        x.split("=")[0]: int(x.split("=")[1]) for x in argon2_split[2].split(",")
    }
    argon2_salt = argon2_hex_to_b64(argon2_split[3])
    argon2_hash = argon2_hex_to_b64(argon2_split[4])

    ph = PasswordHasher(
        time_cost=parameter["t"],
        memory_cost=parameter["m"],
        parallelism=parameter["p"],
        hash_len=int(len(argon2_split[4]) / 2),
        salt_len=int(len(argon2_split[3]) / 2),
    )
    verify_hash = "$" + \
        "$".join(argon2_split[0:3] + [argon2_salt, argon2_hash])
    return ph.verify(verify_hash, password)


class FileServerTest(unittest.TestCase):
    EXECUTABLE = None
    DOCKER = None
    DOCKER_IMAGE = None

    def setUp(self):
        self.req_auth = ("test", "test")
        self.requests = requests
        self.requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    @classmethod
    def setUpClass(cls):
        cls._test_dir = Path(tempfile.mkdtemp(dir='.'))
        cls.base_url = "https://localhost:8080"
        cls.application = None
        cls.container_id = None
        cls._data_dir = cls._test_dir.joinpath("data")
        cls._config_dir = cls._test_dir.joinpath("config")
        cls._data_dir.mkdir(parents=True, exist_ok=True)
        cls._config_dir.mkdir(parents=True, exist_ok=True)
        if cls.EXECUTABLE:
            shutil.copy2(cls.EXECUTABLE, cls._test_dir)
            cls.application = [cls._test_dir.joinpath(cls.EXECUTABLE.name)]
            proc = subprocess.run(
                [cls._test_dir.joinpath(cls.EXECUTABLE.name), "-d"],
                stdout=subprocess.PIPE, check=False,
            )
            if proc.returncode != 0:
                print("Setup FAILED!")
                print(str(proc.stdout))
                sys.exit(1)
            sleep(0.5)
        elif cls.DOCKER:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "-p",
                    "8080:8080",
                    "-v",
                    f"{cls._test_dir.joinpath('data')!s}:/data",
                    "-v",
                    f"{cls._test_dir.joinpath('config')!s}:/config",
                    cls.DOCKER_IMAGE,
                ],
                stdout=subprocess.PIPE, check=False,
            )

            cls.container_id = proc.stdout.decode("UTF-8").strip()
            cls.application = [
                "docker",
                "exec",
                "-it",
                cls.container_id,
                "/file-server",
            ]
            sleep(0.5)
            if proc.returncode != 0:
                print("Setup FAILED!")
                print(str(proc.stdout))
                sys.exit(1)
        else:
            print("Setup FAILED!")
            print("No Test Application!")
            sys.exit(1)

    def test_1_default_config(self):
        with open(self._config_dir.joinpath("config.json"), encoding='utf-8') as fid:
            config = json.load(fid)
        default_config = {
            "rateLimit": {"requestsPerSecond": 1, "burst": 5},
            "daemon": {"logFile": "./config/log", "pidFile": "./config/pid"},
            "userFile": "./config/users.json",
            "storage": "./data",
            "certFolder": "./config/certs",
            "port": 8080,
        }
        self.assertDictEqual(config, default_config)

    def test_2_user(self):
        proc = subprocess.run(
            self.application + ["-u", "test", "-p", "test123"], stdout=subprocess.PIPE, check=False,
        )
        self.assertEqual(proc.returncode, 0)

        with open(self._config_dir.joinpath("users.json"), encoding='utf-8') as fid:
            users = json.load(fid)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "test")
        self.assertTrue(verify_go_argon2_pw(users[0]["password"], "test123"))

        proc = subprocess.run(
            self.application + ["-u", "test2", "-p", "123test"], stdout=subprocess.PIPE, check=False,
        )
        self.assertEqual(proc.returncode, 0)

        with open(self._config_dir.joinpath("users.json"), encoding='utf-8') as fid:
            users = json.load(fid)
        self.assertEqual(len(users), 2)
        self.assertEqual(users[1]["username"], "test2")
        self.assertTrue(verify_go_argon2_pw(users[1]["password"], "123test"))

        proc = subprocess.run(
            self.application + ["-u", "test", "-p", "test", "-f"],
            stdout=subprocess.PIPE, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        with open(self._config_dir.joinpath("users.json"), encoding='utf-8') as fid:
            users = json.load(fid)
        self.assertEqual(users[0]["username"], "test")
        self.assertTrue(verify_go_argon2_pw(users[0]["password"], "test"))

    def test_3_upload(self):
        file_content = "test_upload"
        file = create_testfile(
            content=file_content, suffix='0', directory=self._test_dir)
        upload_url = f"{self.base_url}/upload/"
        with open(file, "rb") as f:
            files = {"file": f}
            response = self.requests.put(
                upload_url, files=files,
                auth=self.req_auth, verify=False,
                timeout=30,
            )
        self.assertEqual(response.status_code, 200)
        uploaded_file = self._data_dir.joinpath(file.name)
        self.assertTrue(uploaded_file.is_file())
        with open(uploaded_file, encoding='utf-8') as fid:
            self.assertEqual(file_content, fid.read())

        file_content = "test_upload_to_folder"
        folders = "test1/test2/test3"
        file = create_testfile(
            content=file_content, suffix='1', directory=self._test_dir)
        upload_url = f"{self.base_url}/upload/{folders}/"
        with open(file, "rb") as f:
            files = {"file": f}
            response = self.requests.put(
                upload_url, files=files,
                auth=self.req_auth, verify=False,
                timeout=30,
            )
        self.assertEqual(response.status_code, 200)
        uploaded_file = self._data_dir.joinpath(f"{folders}/{file.name}")
        self.assertTrue(uploaded_file.is_file())
        with open(uploaded_file, encoding='utf-8') as fid:
            self.assertEqual(file_content, fid.read())

    def test_4_list_files(self):
        response = self.requests.get(
            f"{self.base_url}/files",
            auth=self.req_auth, verify=False,
            timeout=30,
        )
        self.assertEqual(response.status_code, 200)
        response_list = json.loads(response.text)
        self.assertEqual(len(response_list), 2)
        expected = [
            {
                "path": "test1/test2/test3/test_file_1",
                "name": "test_file_1",
                "size": 21,
                "sha256": "460a6c765563cbc2fbde1af001397324d0c21cd58603c4a1a7d5eb32690b2967"},
            {
                "path": "test_file_0",
                "name": "test_file_0",
                "size": 11,
                "sha256": "f82d2cab9dd463d8815593a3207ece0fd44fd227fd0b34c042f28251adbb84e8"}]
        for x in response_list:
            self.assertListEqual(
                list(x.keys()), ["path", "name", "uploadDate", "size", "sha256"])
            x.pop('uploadDate', None)
            found = False
            for y in expected:
                if y['name'] == x['name']:
                    self.assertDictEqual(x, y)
                    found = True
            self.assertTrue(found)

    def test_5_download(self):
        download_dir = Path(tempfile.mkdtemp(dir=self._test_dir))
        file_list = [
            ('test_file_0', 'f82d2cab9dd463d8815593a3207ece0fd44fd227fd0b34c042f28251adbb84e8'),
            ('test1/test2/test3/test_file_1', '460a6c765563cbc2fbde1af001397324d0c21cd58603c4a1a7d5eb32690b2967')]
        for filepath, file_hash in file_list:
            url = f"{self.base_url}/download/{filepath}"
            with self.requests.get(url, timeout=30, auth=self.req_auth, verify=False) as r:
                self.assertEqual(r.status_code, 200)
                with open(download_dir.joinpath(Path(filepath).name), 'wb')as f:
                    f.write(r.content)
            self.assertEqual(
                sha256sum(download_dir.joinpath(Path(filepath).name)), file_hash)

    def test_6_delete(self):
        pass

    @classmethod
    def tearDownClass(cls):
        if cls.DOCKER:
            subprocess.run(
                ["docker", "rm", "-f", cls.container_id], stdout=subprocess.PIPE, check=False,
            )
        shutil.rmtree(cls._test_dir, ignore_errors=True)


if __name__ == "__main__":
    ERROR = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "docker":
            if len(sys.argv) == 3:
                FileServerTest.DOCKER = True
                FileServerTest.DOCKER_IMAGE = sys.argv[2]
            else:
                ERROR = True
        elif Path(sys.argv[1]).is_file():
            FileServerTest.EXECUTABLE = Path(sys.argv[1])
        else:
            ERROR = True
    else:
        ERROR = True
    if ERROR:
        print("Please call like: python e2e-test.py /path/to/go-executable")
        print("or like: python e2e-test.py --docker docker-image-name:tag")
        sys.exit(1)
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)