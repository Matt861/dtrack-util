import requests
from typing import Optional
from datetime import datetime
from Models.Configuration import Configuration
from Models.Project import Project


# Function to upload SBOM.json to Dependency-Track with a specific project name
def upload_sbom(sbom_path: str, project_name: str, base_api_url: str, api_key: str) -> str:

    data = {
        "autoCreate": 'true',
        "projectName": project_name,
        "projectVersion": '0.1.0',
        "classifier": 'Library'
    }

    files = {
        'bom': open(sbom_path, 'rb')
    }

    api_url = f"{base_api_url}/bom"

    response = requests.post(api_url, headers=headers, data=data, files=files, proxies=proxies, verify=cert_file)

    if response.status_code == 200:
        print("SBOM uploaded successfully.")
        return response.json()['token']
    else:
        raise Exception(f"Failed to upload SBOM: {response.status_code}, {response.text}")


def get_project(project_name: str, project_version: str, base_api_url: str, api_key: str) -> Optional[dict]:

    params = {
        'name': project_name,
        'version': project_version
    }

    api_url = f"{base_api_url}/project/lookup"
    response = requests.get(api_url, headers=headers, params=params, proxies=proxies, verify=cert_file)

    if response.status_code == 200:
        project = response.json()
        project_repository.store_project(project)
        return project
    else:
        raise Exception(f"Failed to retrieve project: {response.status_code}, {response.text}")


def get_project_vulnerabilities(base_api_url: str, api_key: str) -> Optional[dict]:

    project_uuid = project_repository.get_project().get('uuid')
    api_url = f"{base_api_url}/vulnerability/project/{project_uuid}"
    response = requests.get(api_url, headers=headers, proxies=proxies, verify=cert_file)

    if response.status_code == 200:
        print("Project vulnerabilities retrieved successfully.")
        vulnerabilities = response.json()
        project_repository.set_vulnerabilities(vulnerabilities)
        return vulnerabilities
    else:
        raise Exception(f"Failed to retrieve project vulnerabilities: {response.status_code}, {response.text}")


def get_project_components(base_api_url: str, api_key: str) -> Optional[dict]:

    project_uuid = project_repository.get_project().get('uuid')
    api_url = f"{base_api_url}/component/project/{project_uuid}"
    response = requests.get(api_url, headers=headers, proxies=proxies, verify=cert_file)

    # Check response
    if response.status_code == 200:
        print("Project components retrieved successfully.")
        components = response.json()
        project_repository.set_components(components)
        return components
    else:
        raise Exception(f"Failed to retrieve project components: {response.status_code}, {response.text}")


if __name__ == '__main__':
    project_repository = Project()
    timestamp = datetime.now().strftime("%m-%d-%Y_%H%M%S")
    SBOM_PATH = "./sboms/maven_sbom.json"
    PROJECT_NAME = f"maven-test-sbom-{timestamp}"
    PROJECT_VERSION = '0.1.0'
    BASE_API_URL = Configuration.dtrack_api_url
    API_KEY = Configuration.dtrack_api_key
    cert_file = "./Combined_pem.pem"
    headers = {
        'X-Api-Key': API_KEY
    }
    proxies = {
        "http": "",
        "https": ""
    }

    token = upload_sbom(SBOM_PATH, PROJECT_NAME, BASE_API_URL, API_KEY)
    dtrack_project = get_project(PROJECT_NAME, PROJECT_VERSION, BASE_API_URL, API_KEY)
    dtrack_vulnerabilities = get_project_vulnerabilities(BASE_API_URL, API_KEY)
    dtrack_components = get_project_components(BASE_API_URL, API_KEY)
    dtrack_direct_components = project_repository.get_direct_components()
    print('breakpoint')
