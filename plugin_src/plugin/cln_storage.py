#!/usr/bin/env python

import sys
from .cln_plugin import CLNPlugin
from .globals import get_plugin_logger


class StorageReadWriteError(Exception): pass


class CLNStorage:  # (Logger):
    """Using the Core Lightning database as storage for the plugin trough lightning-datastore rpc calls."""
    read_key = "swap-provider"  # db key we need to read from (all children are returned)
    write_key = ["swap-provider", "jsondb"]  # the child key we write to

    def __init__(self, *, cln_plugin: CLNPlugin):
        self.logger = get_plugin_logger()
        self.dbwriter = cln_plugin.plugin.rpc.datastore
        self.dbreader = cln_plugin.plugin.rpc.listdatastore
        self.stdinout_mutex = cln_plugin.stdinout_mutex
        self.pos = None
        self.init_pos = None
        self.initialized = False

    def __await__(self):
        return self._fetch_db_content(key=self.read_key).__await__()

    async def _fetch_db_content(self, *, key: str) -> 'CLNStorage':
        """ Fetch all data from the CLN datastore. Key has to be the parent of the key we want to fetch."""
        async with self.stdinout_mutex:
            try:
                raw_data = self.dbreader(key=key)['datastore']
                # {'datastore': [{'key': ['swap-provider', 'jsondb'], 'generation': 0, 'hex': '74657374', 'string': 'test'}]}
            except Exception as e:
                raise StorageReadWriteError(f"Error fetching data from cln datastore: {e}")
        our_data = ""
        for element in raw_data:  # should only contain one element but to be sure we filter for the right write_key
            if element['key'] == self.write_key:
                our_data = element['string']
                break
        self.logger.debug(f"Data fetched from cln datastore: {our_data}")
        self.raw = our_data
        self.pos = len(our_data)
        self.init_pos = self.pos
        self.initialized = True
        return self

    def read(self):
        if not self.initialized:
            raise StorageReadWriteError("CLNStorage has to be awaited for initialization")
        return self.raw

    async def write(self, data: str) -> None:
        """ Replace the jsondb entry with a new db entry (or create one if none exists)."""
        async with self.stdinout_mutex:
            try:
                res = self.dbwriter(key=self.write_key,
                               string=data,
                               mode="create-or-replace")
            except Exception as e:
                raise StorageReadWriteError(f"Failed to write to CLN-DB: {e}")
        if "error" in res:
            raise StorageReadWriteError(f"CLN DB returned error on write: {res}")
        self.init_pos = len(data)  # update initial position
        self.pos = self.init_pos
        self.raw = data  # update raw data to the new content
        self.logger.debug(f"Wrote to CLN db: {res}")
        self.logger.info(f"Saved data to cln datastore")

    async def append(self, data: str) -> None:
        """ append data to jsondb entry."""
        async with self.stdinout_mutex:
            try:
                res = self.dbwriter(key=self.write_key,
                                     string=data,
                                     mode="must-append")
            except Exception as e:
                raise StorageReadWriteError(f"Failed to append data to CLN DB: {e}")
        if "error" in res:
            raise StorageReadWriteError(f"CLN DB returned error on append: {res}")
        self.pos += len(data)
        self.logger.debug(f"Appended data to CLN DB: {res}")

    async def _test_db(self):
        """Test if we can read and write to the cln datastore."""
        try:
            await self.write("1test1")
            await self.append("2test2")
            await self._fetch_db_content(key=self.read_key)
            assert self.read() == "1test12test2"
            print("CLN db test passed", file=sys.stderr)
        except Exception as e:
            raise StorageReadWriteError(f"CLN db test failed: {e}")

    def needs_consolidation(self):
        return self.pos > 2 * self.init_pos
