import hashlib
import hmac
import json
import os
import ssl
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidTag

import main


class SecureShareTests(unittest.TestCase):
    def test_aes_gcm_integrity_and_wrong_key(self):
        salt = bytes(range(16))
        password_key = main.derive_password_key("correct horse battery staple", salt)
        key = main.derive_file_key(password_key, salt)
        original = b"SecureShare crypto test payload"
        nonce, ciphertext = main.encrypt_file(original, key, b"sample.txt")

        self.assertEqual(main.decrypt_file(ciphertext, key, nonce, b"sample.txt"), original)
        self.assertEqual(main.sha256_hex(original), hashlib.sha256(original).hexdigest())
        with self.assertRaises(InvalidTag):
            main.decrypt_file(ciphertext, bytes(32), nonce, b"sample.txt")
        damaged = bytearray(ciphertext)
        damaged[0] ^= 1
        with self.assertRaises(InvalidTag):
            main.decrypt_file(bytes(damaged), key, nonce, b"sample.txt")

    def test_authenticated_https_download(self):
        password = "correct horse battery staple"
        with tempfile.TemporaryDirectory() as shared_dir:
            content = b"downloaded over an authenticated encrypted response"
            file_path = os.path.join(shared_dir, "sample.txt")
            with open(file_path, "wb") as file_handle:
                file_handle.write(content)

            server = main.start_server_background(
                [{"local": shared_dir, "remote": ""}], port=0, password=password
            )
            cert_dir = Path(os.environ.get("APPDATA", Path.home() / ".config")) / "SecureShare"
            context = ssl.create_default_context(cafile=str(cert_dir / "server-cert.pem"))
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor()
            )
            base_url = f"https://{main.get_local_ip()}:{server.server_port}"

            try:
                with self.assertRaises(urllib.error.HTTPError) as response:
                    opener.open(base_url + "/api/list")
                self.assertEqual(response.exception.code, 401)
                response.exception.close()

                bad_challenge = json.loads(opener.open(base_url + "/api/challenge").read())
                bad_login = urllib.request.Request(
                    base_url + "/api/login",
                    data=json.dumps({"nonce": bad_challenge["nonce"], "proof": "00"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as response:
                    opener.open(bad_login)
                self.assertEqual(response.exception.code, 401)
                response.exception.close()

                challenge = json.loads(opener.open(base_url + "/api/challenge").read())
                salt = bytes.fromhex(challenge["salt"])
                nonce = bytes.fromhex(challenge["nonce"])
                password_key = main.derive_password_key(password, salt, challenge["iterations"])
                proof = hmac.new(password_key, nonce, hashlib.sha256).hexdigest()
                login = urllib.request.Request(
                    base_url + "/api/login",
                    data=json.dumps({"nonce": challenge["nonce"], "proof": proof}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                opener.open(login).read()

                listing = json.loads(opener.open(base_url + "/api/list").read())
                self.assertTrue(listing["items"][0]["is_dir"])
                # The shared root is a folder, so list its contents using its root ID.
                contents = json.loads(opener.open(base_url + "/api/list?root=0&path=").read())
                item = contents["items"][0]
                response = opener.open(base_url + "/api/file?root=0&path=sample.txt")
                ciphertext = response.read()
                key = main.derive_file_key(password_key, salt)
                import base64
                decrypted = main.decrypt_file(
                    ciphertext, key, base64.b64decode(response.headers["X-File-Nonce"]), b"sample.txt"
                )
                self.assertEqual(decrypted, content)
                self.assertEqual(response.headers["X-File-SHA256"], hashlib.sha256(decrypted).hexdigest())
                self.assertEqual(item["name"], "sample.txt")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()