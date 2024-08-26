from typing import List
from Models.Vulnerability import Vulnerability


class Component:
    _instances = []

    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.vulnerabilities: List[Vulnerability] = []
        self._store_instance()

    def _store_instance(self):
        self._instances.append(self)

    def add_vulnerability(self, vulnerability: Vulnerability):
        self.vulnerabilities.append(vulnerability)

    @classmethod
    def get_all_instances(cls):
        return cls._instances

    @classmethod
    def find_by_name_and_version(cls, name: str, version: str):
        return next((instance for instance in cls._instances if instance.name == name and instance.version == version), None)
