#!/usr/bin/env python

from .cln_plugin import CLNPlugin
from .globals import get_plugin_logger


# class StorageEncryptionVersion(IntEnum):
#     PLAINTEXT = 0
#     USER_PASSWORD = 1
#     XPUB_PASSWORD = 2


class StorageReadWriteError(Exception): pass

# class StorageOnDiskUnexpectedlyChanged(Exception): pass


class CLNStorage:  # (Logger):
    """Using the Core Lightning database as storage for the plugin trough lightning-datastore rpc calls."""
    datastore_key = "swap-provider"

    def __init__(self, *, cln_plugin: CLNPlugin):
        self.logger = get_plugin_logger()
        self.datastore = cln_plugin.plugin.rpc.datastore
        self.stdinout_mutex = cln_plugin.stdinout_mutex
        self.raw = self.fetch_all_data(key=self.datastore_key)
        # self.path = standardize_path(path)
        # self._file_exists = bool(self.path and os.path.exists(self.path))
        # self.logger.info(f"wallet path {self.path}")
        # self.pubkey = None
        # self.decrypted = ''
        # try:
        #     test_read_write_permissions(self.path)
        # except IOError as e:
        #     raise StorageReadWriteError(e) from e
        # if self.file_exists():
        #     with open(self.path, "rb") as f:
        #         self.raw = f.read().decode("utf-8")
        #         self.pos = f.seek(0, os.SEEK_END)
        #         self.init_pos = self.pos
        #     self._encryption_version = self._init_encryption_version()
        # else:
        #     self.raw = ''
        #     self._encryption_version = StorageEncryptionVersion.PLAINTEXT
        #     self.pos = 0
        #     self.init_pos = 0

    def fetch_all_data(self, *, key: str) -> str:
        """
        Fetch all data from the CLN datastore. Only called on init,
        so stdionout mutex not neccessary
        """
        try:
            raw_data = self.datastore(key=key)["string"]
            self.logger.debug(f"Data fetched from cln datastore:\n{raw_data}")
        except Exception as e:
            raise StorageReadWriteError(f"Error fetching data from cln datastore: {e}")
        return raw_data

    def read(self):
        return self.raw

    async def write(self, data: str) -> None:
        async with self.stdinout_mutex:
            try:
                res = self.datastore(key="datastore-key",
                               string=data.encode("utf-8"),
                               mode="create-or-replace")
            except Exception as e:
                raise StorageReadWriteError(f"Failed to write to CLN-DB: {e}")
        if "error" in res:
            raise StorageReadWriteError(f"CLN DB returned error on write: {res}")
        self.logger.debug(f"Wrote to CLN db: {res}")
        self.logger.info(f"Saved data to cln datastore")
        # self._file_exists = True

    async def append(self, data: str) -> None:
        """ append data to db entry."""
        async with self.stdinout_mutex:
            try:
                res = self.datastore(key=self.datastore_key,
                                     string=data.encode("utf-8"),
                                     mode="must-append")
            except Exception as e:
                raise StorageReadWriteError(f"Failed to append data to CLN DB: {e}")
        if "error" in res:
            raise StorageReadWriteError(f"CLN DB returned error on append: {res}")
        self.logger.debug(f"Appended data to CLN DB: {res}")


    # def needs_consolidation(self):
    #     return self.pos > 2 * self.init_pos
    #
    # def file_exists(self) -> bool:
    #     return self._file_exists



    # def is_past_initial_decryption(self) -> bool:
    #     """Return if storage is in a usable state for normal operations.
    #
    #     The value is True exactly
    #         if encryption is disabled completely (self.is_encrypted() == False),
    #         or if encryption is enabled but the contents have already been decrypted.
    #     """
    #     return not self.is_encrypted() or bool(self.pubkey)
    #
    # def is_encrypted(self) -> bool:
    #     """Return if storage encryption is currently enabled."""
    #     return self.get_encryption_version() != StorageEncryptionVersion.PLAINTEXT
    #
    # def is_encrypted_with_user_pw(self) -> bool:
    #     return self.get_encryption_version() == StorageEncryptionVersion.USER_PASSWORD
    #
    # def is_encrypted_with_hw_device(self) -> bool:
    #     return self.get_encryption_version() == StorageEncryptionVersion.XPUB_PASSWORD
    #
    # def get_encryption_version(self):
    #     """Return the version of encryption used for this storage.
    #
    #     0: plaintext / no encryption
    #
    #     ECIES, private key derived from a password,
    #     1: password is provided by user
    #     2: password is derived from an xpub; used with hw wallets
    #     """
    #     return self._encryption_version
    #
    # def _init_encryption_version(self):
    #     try:
    #         magic = base64.b64decode(self.raw)[0:4]
    #         if magic == b'BIE1':
    #             return StorageEncryptionVersion.USER_PASSWORD
    #         elif magic == b'BIE2':
    #             return StorageEncryptionVersion.XPUB_PASSWORD
    #         else:
    #             return StorageEncryptionVersion.PLAINTEXT
    #     except Exception:
    #         return StorageEncryptionVersion.PLAINTEXT
    #
    # @staticmethod
    # def get_eckey_from_password(password):
    #     if password is None:
    #         password = ""
    #     secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
    #     ec_key = ecc.ECPrivkey.from_arbitrary_size_secret(secret)
    #     return ec_key
    #
    # def _get_encryption_magic(self):
    #     v = self._encryption_version
    #     if v == StorageEncryptionVersion.USER_PASSWORD:
    #         return b'BIE1'
    #     elif v == StorageEncryptionVersion.XPUB_PASSWORD:
    #         return b'BIE2'
    #     else:
    #         raise WalletFileException('no encryption magic for version: %s' % v)
    #
#    def decrypt(self, password) -> None:
#         """Raises an InvalidPassword exception on invalid password"""
#         if self.is_past_initial_decryption():
#             return
#         ec_key = self.get_eckey_from_password(password)
#         if self.raw:
#             enc_magic = self._get_encryption_magic()
#             s = zlib.decompress(crypto.ecies_decrypt_message(ec_key, self.raw, magic=enc_magic))
#             s = s.decode('utf8')
#         else:
#             s = ''
#         self.pubkey = ec_key.get_public_key_hex()
#         self.decrypted = s

    # def encrypt_before_writing(self, plaintext: str) -> str:
    #     s = plaintext
    #     if self.pubkey:
    #         self.decrypted = plaintext
    #         s = bytes(s, 'utf8')
    #         c = zlib.compress(s, level=zlib.Z_BEST_SPEED)
    #         enc_magic = self._get_encryption_magic()
    #         public_key = ecc.ECPubkey(bfh(self.pubkey))
    #         s = crypto.ecies_encrypt_message(public_key, c, magic=enc_magic)
    #         s = s.decode('utf8')
    #     return s

    # def check_password(self, password: Optional[str]) -> None:
    #     """Raises an InvalidPassword exception on invalid password"""
    #     if not self.is_encrypted():
    #         if password is not None:
    #             raise InvalidPassword("password given but wallet has no password")
    #         return
    #     if not self.is_past_initial_decryption():
    #         self.decrypt(password)  # this sets self.pubkey
    #     assert self.pubkey is not None
    #     if self.pubkey != self.get_eckey_from_password(password).get_public_key_hex():
    #         raise InvalidPassword()

    # def set_password(self, password, enc_version=None):
    #     """Set a password to be used for encrypting this storage."""
    #     if not self.is_past_initial_decryption():
    #         raise Exception("storage needs to be decrypted before changing password")
    #     if enc_version is None:
    #         enc_version = self._encryption_version
    #     if password and enc_version != StorageEncryptionVersion.PLAINTEXT:
    #         ec_key = self.get_eckey_from_password(password)
    #         self.pubkey = ec_key.get_public_key_hex()
    #         self._encryption_version = enc_version
    #     else:
    #         self.pubkey = None
    #         self._encryption_version = StorageEncryptionVersion.PLAINTEXT

    # def basename(self) -> str:
    #     return os.path.basename(self.path)

