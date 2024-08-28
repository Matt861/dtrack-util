import json
from typing import Optional, List


class Project:
    _instance = None

    def __init__(self):
        self._project_data = None
        self._vulnerabilities = None
        self._components = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Project, cls).__new__(cls)
            cls._instance._project_data = None
            cls._instance._components = None
            cls._instance._vulnerabilities = None
        return cls._instance

    def store_project(self, project_data: dict):
        self._project_data = project_data

    def get_project(self) -> Optional[dict]:
        return self._project_data

    def set_components(self, components: list[dict]):
        self._components = components

    def get_components(self) -> List[dict]:
        return self._components

    def get_direct_components(self) -> List[dict]:
        return json.loads(self._project_data.get('directDependencies'))

    def set_vulnerabilities(self, vulnerabilities: list[dict]):
        self._vulnerabilities = vulnerabilities

    def get_vulnerabilities(self) -> List[dict]:
        return self._vulnerabilities
