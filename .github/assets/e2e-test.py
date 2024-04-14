import os
import requests
import tempfile
import unittest
import sys
import subprocess
import json
from argon2 import PasswordHasher
from pathlib import Path
import shutil
from time import sleep
import base64


def verify_go_argon2_pw(go_argon2, password):
    def argon2_hex_to_b64(hex):
        return (
            base64.encodebytes(bytes.fromhex(hex))
            .decode("utf-8")
            .strip()
            .replace("=", "")
        )

    argon2_split = go_argon2.split("$")[1:]

    parameter = {
        x.split("=")[0]: int(x.split("=")[1]) for x in argon2_split[2].split(",")
    }
    salt = argon2_hex_to_b64(argon2_split[3])
    hash = argon2_hex_to_b64(argon2_split[4])

    ph = PasswordHasher(
        time_cost=parameter["t"],
        memory_cost=parameter["m"],
        parallelism=parameter["p"],
        hash_len=int(len(argon2_split[4]) / 2),
        salt_len=int(len(argon2_split[3]) / 2),
    )
    verify_hash = "$" + "$".join(argon2_split[0:3] + [salt, hash])
    return ph.verify(verify_hash, password)


class FileServerTest(unittest.TestCase):
    EXECUTABLE = None
    DOCKER = None
    DOCKER_IMAGE = None

    def setUp(self):
        self.req_auth = ("test", "test")

    @classmethod
    def setUpClass(self):
        self._test_dir = Path(tempfile.mkdtemp())
        self.base_url = "https://localhost:8080"
        self.application = None
        self.container_id = None
        self._data_dir = self._test_dir.joinpath("data")
        self._config_dir = self._test_dir.joinpath("config")
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._config_dir.mkdir(parents=True, exist_ok=True)
        if self.EXECUTABLE:
            shutil.copy2(self.EXECUTABLE, self._test_dir)
            self.application = [self._test_dir.joinpath(self.EXECUTABLE.name)]
            proc = subprocess.run(
                [self._test_dir.joinpath(self.EXECUTABLE.name), "-d"],
                stdout=subprocess.PIPE,
            )
            if proc.returncode != 0:
                print("Setup FAILED!")
                print(str(proc.stdout))
                sys.exit(1)
            sleep(0.5)
        elif self.DOCKER:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "-p",
                    "8080:8080",
                    "-v",
                    f"{str(self._test_dir.joinpath('data'))}:/data",
                    "-v",
                    f"{str(self._test_dir.joinpath('config'))}:/config",
                    self.DOCKER_IMAGE,
                ],
                stdout=subprocess.PIPE,
            )

            self.container_id = proc.stdout.decode("UTF-8").strip()
            self.application = [
                "docker",
                "exec",
                "-it",
                self.container_id,
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

    def _create_tempfile(self, content=""):
        fid, filename = tempfile.mkstemp(dir=self._test_dir)
        with os.fdopen(fid, "w") as tmp:
            tmp.write(content)
        return Path(filename)

    def test_default_config(self):
        with open(self._config_dir.joinpath("config.json")) as fid:
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

    def test_add_user(self):
        proc = subprocess.run(
            self.application + ["-u", "test", "-p", "test123"], stdout=subprocess.PIPE
        )
        self.assertEqual(proc.returncode, 0)

        with open(self._config_dir.joinpath("users.json"), "r") as fid:
            users = json.load(fid)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "test")
        self.assertTrue(verify_go_argon2_pw(users[0]["password"], "test123"))

        proc = subprocess.run(
            self.application + ["-u", "test2", "-p", "123test"], stdout=subprocess.PIPE
        )
        self.assertEqual(proc.returncode, 0)

        with open(self._config_dir.joinpath("users.json"), "r") as fid:
            users = json.load(fid)
        self.assertEqual(len(users), 2)
        self.assertEqual(users[1]["username"], "test2")
        self.assertTrue(verify_go_argon2_pw(users[1]["password"], "123test"))

    def test_update_user(self):
        proc = subprocess.run(
            self.application + ["-u", "test", "-p", "test", "-f"],
            stdout=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0)
        with open(self._config_dir.joinpath("users.json"), "r") as fid:
            users = json.load(fid)
        self.assertEqual(users[0]["username"], "test")
        self.assertTrue(verify_go_argon2_pw(users[0]["password"], "test"))

    def test_upload(self):
        requests.packages.urllib3.disable_warnings()
        file_content = "test_upload"
        file = self._create_tempfile(content=file_content)
        upload_url = f"{self.base_url}/upload/"
        with open(file, "rb") as f:
            files = {"file": f}
            response = requests.put(
                upload_url, files=files, auth=self.req_auth, verify=False
            )
        self.assertEqual(response.status_code, 200)
        uploaded_file = self._data_dir.joinpath(file.name)
        self.assertTrue(uploaded_file.is_file())
        with open(uploaded_file, "r") as fid:
            self.assertEqual(file_content, fid.read())

    def test_upload_to_folder(self):
        requests.packages.urllib3.disable_warnings()
        file_content = "test_upload_to_folder"
        folders = "test1/test2/test3"
        file = self._create_tempfile(content=file_content)
        upload_url = f"{self.base_url}/upload/{folders}/"
        with open(file, "rb") as f:
            files = {"file": f}
            response = requests.put(
                upload_url, files=files, auth=self.req_auth, verify=False
            )
        self.assertEqual(response.status_code, 200)
        uploaded_file = self._data_dir.joinpath(f"{folders}/{file.name}")
        self.assertTrue(uploaded_file.is_file())
        with open(uploaded_file, "r") as fid:
            self.assertEqual(file_content, fid.read())

    # def test_list_files(self):
    #     # List files
    #     list_files_url = f"{self.base_url}/files"
    #     response = requests.get(list_files_url, auth=("username", "password"))
    #     self.assertEqual(response.status_code, 200)
    #     files = response.json()
    #     self.assertIsInstance(files, list)

    # def test_download(self):
    #     # Download the uploaded file
    #     download_url = f"{self.base_url}/download/test.txt"
    #     response = requests.get(download_url, auth=("username", "password"))
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(response.content, file_content)

    # def test_delete(self):
    #     # Delete the uploaded file
    #     delete_url = f"{self.base_url}/delete/path/to/test.txt"
    #     response = requests.delete(delete_url, auth=("username", "password"))
    #     self.assertEqual(response.status_code, 200)

    #     # Ensure the file is deleted
    #     download_url = f"{self.base_url}/download/path/to/test.txt"
    #     response = requests.get(download_url, auth=("username", "password"))
    #     self.assertEqual(response.status_code, 404)

    @classmethod
    def tearDownClass(self):
        if self.DOCKER:
            subprocess.run(
                ["docker", "rm", "-f", self.container_id], stdout=subprocess.PIPE
            )
        shutil.rmtree(self._test_dir, ignore_errors=True)


if __name__ == "__main__":
    error = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "docker":
            if len(sys.argv) == 3:
                FileServerTest.DOCKER = True
                FileServerTest.DOCKER_IMAGE = sys.argv[2]
            else:
                error = True
        else:
            if Path(sys.argv[1]).is_file():
                FileServerTest.EXECUTABLE = Path(sys.argv[1])
            else:
                error = True
    else:
        error = True
    if error:
        print("Please call like: python e2e-test.py /path/to/go-executable")
        print("or like: python e2e-test.py --docker docker-image-name:tag")
        sys.exit(1)
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
