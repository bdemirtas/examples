from dataclasses import dataclass

import clamd


class VirusScan:
    def __enter__(self):
        self.clamd = clamd.ClamdUnixSocket()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type == clamd.ConnectionError:
            print("No virus scanner found")
        else:
            self.clamd._close_socket()

    def scan_files(self, path):
        result = self.clamd.scan(path)
        return VirusScanFiles(result)


class VirusScanFiles:
    def __init__(self, result):
        results = [
            VirusScanFileStatus(filename=k, reason=v[1], status=v[0])
            for k, v in result.items()
        ]
        self.results = results

    def __len__(self):
        return len(self.results)

    def __getitem__(self, index):
        if index >= len(self):
            raise IndexError
        return self.results[index]


@dataclass
class VirusScanFileStatus:
    filename: str
    reason: str
    status: str


if __name__ == "__main__":
    with VirusScan() as virus_scanner:
        for result in virus_scanner.scan_files("/tmp"):
            print(result)
