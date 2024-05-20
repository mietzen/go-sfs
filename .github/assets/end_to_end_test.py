# pylint: disable=missing-function-docstring, missing-class-docstring, missing-module-docstring, line-too-long

import base64
import hashlib
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from time import sleep

import requests
from argon2 import PasswordHasher

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')


def run_process(cmd, cwd=None):
    logging.debug(f"Running command: {' '.join([str(x) for x in cmd])}, cwd={cwd}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False, cwd=cwd)
    logging.debug(f"Command result: {result.stdout.decode()}")
    return result


def load_json_file(filepath):
    logging.debug(f"Loading JSON file from {filepath}")
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def create_testfile(suffix="", content="", directory=None):
    filepath = Path(f"test_file_{suffix}")
    if directory:
        directory.mkdir(parents=True, exist_ok=True)
        filepath = directory.joinpath(filepath)
    logging.debug(f"Creating test file at {filepath}")
    with open(filepath, "w", encoding="utf-8") as fid:
        fid.write(content)
    return Path(filepath)


def sha256sum(filename):
    logging.debug(f"Calculating sha256sum for {filename}")
    with open(filename, "rb", buffering=0) as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


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
    DEFAULT_CONFIG = {
        "rateLimit": {"requestsPerSecond": 1, "burst": 5},
        "daemon": {"logFile": "./config/log", "pidFile": "./config/pid"},
        "userFile": "./config/users.json",
        "storage": "./data",
        "certFolder": "./config/certs",
        "port": 8080,
        "reverseProxy": False,
        "baseURL": "0.0.0.0",
    }
    TEST_FILES = [
        {
            "path": "test_file_0",
            "name": "test_file_0",
            "content": "test_upload",
            "size": 11,
            "sha256": "f82d2cab9dd463d8815593a3207ece0fd44fd227fd0b34c042f28251adbb84e8"},
        {
            "path": "test1/test2/test3/test_file_1",
            "name": "test_file_1",
            "content": "test_upload_to_folder",
            "size": 21,
            "sha256": "460a6c765563cbc2fbde1af001397324d0c21cd58603c4a1a7d5eb32690b2967"}]
    TEST_USERS = [
        {"n": "test", "p": "test123"},
        {"n": "test2", "p": "123test"}]

    def setUp(self):
        self.req_auth = ("test", "test")
        self.requests = requests
        self.requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    @classmethod
    def setUpClass(cls):
        logging.debug("Setting up class...")
        cls._test_dir = Path(tempfile.mkdtemp(dir="."))
        cls.base_url = f"https://127.0.0.1:{cls.DEFAULT_CONFIG['port']}"
        cls.application = None
        cls.container_id = None
        cls.cwd = None
        cls.proc = None
        cls._data_dir = cls._test_dir.joinpath("data")
        cls._config_dir = cls._test_dir.joinpath("config")
        cls._data_dir.mkdir(parents=True, exist_ok=True)
        cls._config_dir.mkdir(parents=True, exist_ok=True)
        if cls.EXECUTABLE:
            shutil.copy2(cls.EXECUTABLE, cls._test_dir)
            cls.application = [cls._test_dir.joinpath(cls.EXECUTABLE.name)]
            cls.cwd = cls._test_dir
            proc = run_process(
                [str(cls._test_dir.joinpath(cls.EXECUTABLE.name)), "-d"],
                cwd=cls.cwd)
            if proc.returncode != 0:
                logging.error("Setup FAILED! Executable failed to start.")
                logging.error(str(proc.stdout))
                sys.exit(1)
            sleep(1)
        elif cls.DOCKER:
            proc = run_process(
                [
                    "docker",
                    "run",
                    "-d",
                    "-p",
                    "127.0.0.1:8080:8080",
                    "-v",
                    f"{cls._test_dir.joinpath('data')!s}:/data",
                    "-v",
                    f"{cls._test_dir.joinpath('config')!s}:/config",
                    cls.DOCKER_IMAGE,
                ])

            cls.container_id = proc.stdout.decode("UTF-8").strip()
            cls.application = [
                "docker",
                "exec",
                cls.container_id,
                "/file-server",
            ]
            if proc.returncode != 0:
                logging.error("Setup FAILED! Docker container failed to start.")
                logging.error(str(proc.stdout))
                sys.exit(1)
            sleep(0.5)
        else:
            logging.error("Setup FAILED! No Test Application provided.")
            sys.exit(1)

    def test_1_default_config(self):
        logging.debug("Testing default configuration...")
        config = load_json_file(self._config_dir.joinpath("config.json"))
        self.assertDictEqual(config, self.DEFAULT_CONFIG)

    def test_2_user(self):
        logging.debug("Testing user creation and verification...")
        for idx, user in enumerate(self.TEST_USERS):
            proc = run_process(self.application +
                               ["-u", user["n"], "-p", user["p"]],
                               cwd=self.cwd)
            self.assertEqual(proc.returncode, 0)
            users = load_json_file(self._config_dir.joinpath("users.json"))
            self.assertEqual(len(users), idx + 1)
            self.assertEqual(users[idx]["username"], user["n"])
            self.assertTrue(verify_go_argon2_pw(
                users[idx]["password"], user["p"]))

        proc = run_process(
            self.application +
            ["-u", "test", "-p", "test", "-f"],
            cwd=self.cwd)
        self.assertEqual(proc.returncode, 0)
        users = load_json_file(self._config_dir.joinpath("users.json"))
        self.assertEqual(users[0]["username"], "test")
        self.assertTrue(verify_go_argon2_pw(users[0]["password"], "test"))

    def test_3_upload(self):
        logging.debug("Testing file upload...")
        for file_data in self.TEST_FILES:
            suffix = file_data["name"].rsplit("_", maxsplit=1)[-1]
            file = create_testfile(
                content=file_data["content"], suffix=suffix, directory=self._test_dir)
            if file_data["path"] == file_data["name"]:
                upload_url = f"{self.base_url}/"
            else:
                folders = str(Path(file_data["path"]).parents[0])
                upload_url = f"{self.base_url}/{folders}/"
            with open(file, "rb") as f:
                files = {"file": f}
                response = self.requests.put(
                    upload_url, files=files,
                    auth=self.req_auth, verify=False,
                    timeout=30,
                )
            self.assertEqual(response.status_code, 201)
            uploaded_file = self._data_dir.joinpath(file_data["path"])
            self.assertTrue(uploaded_file.is_file())
            with open(uploaded_file, encoding="utf-8") as fid:
                self.assertEqual(file_data["content"], fid.read())
            sleep(0.5)

    def test_4_list_files(self):
        logging.debug("Testing file listing...")
        response = self.requests.get(
            f"{self.base_url}/files",
            auth=self.req_auth, verify=False,
            timeout=30,
        )
        self.assertEqual(response.status_code, 200)
        response_list = json.loads(response.text)
        self.assertEqual(len(response_list), 2)
        expected = [{k: v for k, v in d.items() if k != "content"}
                    for d in self.TEST_FILES]
        for x in response_list:
            self.assertListEqual(
                list(x.keys()), ["path", "name", "uploadDate", "size", "sha256"])
            x.pop("uploadDate", None)
            found = False
            for y in expected:
                if y["name"] == x["name"]:
                    self.assertDictEqual(x, y)
                    found = True
            self.assertTrue(found)
            sleep(0.5)

    def test_5_download(self):
        logging.debug("Testing file download...")
        download_dir = Path(tempfile.mkdtemp(dir=self._test_dir))
        for file_meta_data in self.TEST_FILES:
            url = f"{self.base_url}/{file_meta_data['path']}"
            with self.requests.get(url, timeout=30, auth=self.req_auth, verify=False) as r:
                self.assertEqual(r.status_code, 200)
                with open(download_dir.joinpath(Path(file_meta_data["path"]).name), "wb") as f:
                    f.write(r.content)
            self.assertEqual(
                sha256sum(download_dir.joinpath(Path(file_meta_data["path"]).name)), file_meta_data["sha256"])
            sleep(0.5)

    def test_6_delete(self):
        logging.debug("Testing file deletion...")
        for file_data in self.TEST_FILES:
            if file_data["path"] == file_data["name"]:
                delete_url = f"{self.base_url}/{file_data['name']}"
            else:
                folder = str(Path(file_data["path"]).parents[-2])
                delete_url = f"{self.base_url}/{folder}/"
            response = self.requests.delete(
                delete_url,
                auth=self.req_auth, verify=False,
                timeout=30,
            )
            self.assertEqual(response.status_code, 200)
            deleted_file = self._data_dir.joinpath(file_data["path"])
            self.assertFalse(deleted_file.exists())
            sleep(0.5)

    def test_7_rate_limit(self):
        logging.debug("Testing rate limit...")
        burst = int(self.DEFAULT_CONFIG["rateLimit"]["burst"])
        sleep(burst)  # Cool down
        for i in range(1, burst + 2):
            response = self.requests.get(
                f"{self.base_url}/files",
                auth=self.req_auth, verify=False,
                timeout=30)
            if i <= burst:
                self.assertEqual(response.status_code, 200)
            elif i > burst:
                self.assertEqual(response.status_code, 429)
        sleep(1)

    def test_8_bad_auth(self):
        logging.debug("Testing authentication failure...")
        response = self.requests.get(
            f"{self.base_url}/files",
            auth=("Wrong", "User"), verify=False,
            timeout=30)
        self.assertEqual(response.status_code, 401)

    @classmethod
    def tearDownClass(cls):
        logging.debug("Tearing down class...")
        if cls.DOCKER:
            subprocess.run(
                ["docker", "rm", "-f", cls.container_id], stdout=subprocess.PIPE, check=False,
            )
        else:
            subprocess.run(
                ["killall", cls.EXECUTABLE.name], stdout=subprocess.PIPE, check=False,
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
        logging.error("Invalid call. Please provide a valid executable or Docker image.")
        logging.error("Usage: python e2e-test.py /path/to/go-executable or python e2e-test.py --docker docker-image-name:tag")
        sys.exit(1)
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
