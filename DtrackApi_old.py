import requests
import time
from typing import Optional, List

from Models.Component import Component
from Models.Configuration import Configuration
from Models.Vulnerability import Vulnerability


# Function to upload SBOM.json to Dependency-Track with a specific project name
def upload_sbom(sbom_path: str, project_name: str, api_url: str, api_key: str) -> str:
    headers = {
        'X-Api-Key': api_key,
    }

    data = {
        "autoCreate": 'true',
        "projectName": project_name,
        "projectVersion": '0.1.0',
        "classifier": 'Library'
    }

    files = {
        'bom': open(sbom_path, 'rb')
    }

    response = requests.put(f'{api_url}/api/v1/bom', headers=headers, data=data, files=files, proxies=proxies, verify=cert_file)

    if response.status_code == 200:
        print("SBOM uploaded successfully.")
        return response.json()['token']
    else:
        raise Exception(f"Failed to upload SBOM: {response.status_code}, {response.text}")


# Function to retrieve vulnerability information associated with the SBOM components
def get_vulnerability_info(token: str, api_url: str, api_key: str) -> List[Component]:
    headers = {
        'X-Api-Key': api_key,
        'Accept': 'application/json'
    }

    # Wait for the processing to complete
    while True:
        status_response = requests.get(f'{api_url}/api/v1/bom/token/{token}', headers=headers)
        status_data = status_response.json()

        if not status_data['processing']:
            break

        time.sleep(5)  # Wait before checking again

    # Get the project details
    project_response = requests.get(f'{api_url}/api/v1/project', headers=headers)
    project_data = project_response.json()

    components_info = []

    # Loop through the components and retrieve their vulnerabilities
    for project in project_data:
        component_response = requests.get(f'{api_url}/api/v1/project/{project["uuid"]}/component', headers=headers)
        components = component_response.json()

        for component in components:
            component_info = Component(name=component['name'], version=component.get('version', 'N/A'))

            vuln_response = requests.get(f'{api_url}/api/v1/component/{component["uuid"]}/vulnerability',
                                         headers=headers)
            vulns = vuln_response.json()

            for vuln in vulns:
                vulnerability_info = Vulnerability(
                    severity=vuln['severity'],
                    vulnerability_id=vuln['vulnId'],
                    description=vuln.get('description')
                )
                component_info.add_vulnerability(vulnerability_info)

            components_info.append(component_info)

    return components_info


# Function to retrieve a project by its name from Dependency-Track
def get_project_by_name(project_name: str, api_url: str, api_key: str) -> Optional[dict]:
    headers = {
        'X-Api-Key': api_key,
        'Accept': 'application/json'
    }

    response = requests.get(f'{api_url}/api/v1/project', headers=headers)

    if response.status_code == 200:
        projects = response.json()
        for project in projects:
            if project['name'].lower() == project_name.lower():
                return project
        print(f"Project '{project_name}' not found.")
    else:
        raise Exception(f"Failed to retrieve projects: {response.status_code}, {response.text}")

    return None


# Example usage:
if __name__ == "__main__":
    SBOM_PATH = "path/to/your/SBOM.json"
    PROJECT_NAME = "Your Project Name"
    API_URL = Configuration.dtrack_api_url
    API_KEY = Configuration.dtrack_api_key
    cert_file = ""
    proxies = {
        "http": "",
        "https": ""
    }

    try:
        # Retrieve the project by name
        project = get_project_by_name(PROJECT_NAME, API_URL, API_KEY)
        if project:
            print(f"Project found: {project['name']} (UUID: {project['uuid']})")

        # Upload the SBOM with the project name
        token = upload_sbom(SBOM_PATH, PROJECT_NAME, API_URL, API_KEY)

        # Retrieve component and vulnerability information
        components_info_list = get_vulnerability_info(token, API_URL, API_KEY)

        # Process and display the retrieved information
        for component_info in components_info_list:
            print(f"Component: {component_info.name} (Version: {component_info.version})")
            for vulnerability in component_info.vulnerabilities:
                print(f"  - Severity: {vulnerability.severity}, Vulnerability ID: {vulnerability.vulnerability_id}, "
                      f"Description: {vulnerability.description}")

        # Retrieve all stored instances (example)
        all_components = Component.get_all_instances()
        all_vulnerabilities = Vulnerability.get_all_instances()

        print("\nAll Components:")
        for component in all_components:
            print(f"Component: {component.name} (Version: {component.version})")

        print("\nAll Vulnerabilities:")
        for vulnerability in all_vulnerabilities:
            print(f"Vulnerability ID: {vulnerability.vulnerability_id}, Severity: {vulnerability.severity}")

    except Exception as e:
        print(f"An error occurred: {e}")
