from typing import Optional, Dict, List

class Project:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Project, cls).__new__(cls)
            cls._instance._project_data = None
            cls._instance._components = {}
            cls._instance._direct_components = {}
            cls._instance._vulnerabilities = {}
        return cls._instance

    def store_project(self, project_data: dict):
        self._project_data = project_data

    def get_project(self) -> Optional[dict]:
        return self._project_data

    def store_component(self, name: str, version: str, component_data: dict):
        key = f"{name}:{version}"
        self._components[key] = component_data

    def store_components(self, components: Dict[str, dict]):
        for key, component_data in components.items():
            self._components[key] = component_data

    def get_component(self, name: str, version: str) -> Optional[dict]:
        key = f"{name}:{version}"
        return self._components.get(key)

    def get_all_components(self) -> List[dict]:
        return list(self._components.values())

    def store_direct_component(self, name: str, version: str, component_data: dict):
        key = f"{name}:{version}"
        self._direct_components[key] = component_data

    def store_direct_components(self, components: Dict[str, dict]):
        for key, component_data in components.items():
            self._direct_components[key] = component_data

    def get_direct_component(self, name: str, version: str) -> Optional[dict]:
        key = f"{name}:{version}"
        return self._direct_components.get(key)

    def get_all_direct_components(self) -> List[dict]:
        return list(self._direct_components.values())

    def store_vulnerability(self, vulnerability_id: str, vulnerability_data: dict):
        self._vulnerabilities[vulnerability_id] = vulnerability_data

    def store_vulnerabilities(self, vulnerabilities: Dict[str, dict]):
        for vulnerability_id, vulnerability_data in vulnerabilities.items():
            self._vulnerabilities[vulnerability_id] = vulnerability_data

    def get_vulnerability(self, vulnerability_id: str) -> Optional[dict]:
        return self._vulnerabilities.get(vulnerability_id)

    def get_all_vulnerabilities(self) -> List[dict]:
        return list(self._vulnerabilities.values())

# Example usage
# def get_project_by_name(project_name: str, api_url: str, api_key: str) -> Optional[dict]:
#     # Assuming the function fetches project data from Dependency-Track
#     # ...
#     if project_data_found:
#         project_repository = Project()
#         project_repository.store_project(project_data)
#         return project_data
#     else:
#         return None
#
# def store_component_example():
#     project_repository = Project()
#     component_data = {
#         'name': 'example-component',
#         'version': '1.0.0',
#         'other_data': 'some data'
#     }
#     project_repository.store_component('example-component', '1.0.0', component_data)
#
# def store_vulnerability_example():
#     project_repository = Project()
#     vulnerability_data = {
#         'vulnerability_id': 'CVE-2023-1234',
#         'severity': 'High',
#         'description': 'An example vulnerability'
#     }
#     project_repository.store_vulnerability('CVE-2023-1234', vulnerability_data)
