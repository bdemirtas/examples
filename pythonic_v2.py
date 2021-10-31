import os
from abc import ABC, abstractmethod

import attr
import pyclamd


class VirusScanConnectionError(Exception):
    pass


@attr.s(frozen=True)
class VirusScanFiles(ABC):
    """Scanned file status list"""

    @abstractmethod
    def __len__(self):
        """virus scanned file list size"""
        raise NotImplementedError

    @abstractmethod
    def __getitem__(self, index):
        """retrieve file by index"""
        raise NotImplementedError


@attr.s(frozen=True)
class VirusScan(ABC):
    """Virus Scan Files list representation"""

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type == VirusScanConnectionError:
            print("No virus scanner found")
        else:
            self.close()

    @abstractmethod
    def open(self):
        """Open connection with the virus scanner"""
        raise NotImplementedError

    @abstractmethod
    def close(self):
        """Close connection with the virus scanner"""
        raise NotImplementedError

    @abstractmethod
    def scan_files(self, path) -> VirusScanFiles:
        """Scan one or more files"""
        raise NotImplementedError


@attr.s(frozen=True)
class ClamdVirusScanFile:
    """Virus scanned file result"""

    filename = attr.ib()
    status = attr.ib()
    reason = attr.ib()


@attr.s(frozen=True)
class ClamdVirusScanFiles(VirusScanFiles):
    results = attr.ib()
    data = attr.ib(init=False)

    def __attrs_post_init__(self):
        data = [
            ClamdVirusScanFile(filename=k, reason=v[1], status=v[0])
            for k, v in self.results.items()
        ]
        object.__setattr__(self, "data", data)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        if index >= len(self):
            raise IndexError
        return self.data[index]


@attr.s(frozen=True)
class ClamdVirusScan(VirusScan):
    """Clamd virus scan connection"""

    socket = attr.ib(default=None)
    _client = attr.ib(default=None)

    def open(self):
        try:
            if not self._client:
                object.__setattr__(
                    self, "_client", pyclamd.ClamdUnixSocket(self.socket)
                )
        except pyclamd.ConnectionError:
            raise VirusScanConnectionError

    def close(self):
        self._client._close_socket()

    def scan_files(self, path):
        if os.path.isfile(path):
            return ClamdVirusScanFiles(self._client.scan_file(path))

        if os.path.isdir(path):
            return ClamdVirusScanFiles(self._client.multiscan_file(path))

        return ClamdVirusScanFiles([])


if __name__ == "__main__":
    with ClamdVirusScan() as virus_scanner:
        for file in virus_scanner.scan_files("/tmp/"):
            print(file)
