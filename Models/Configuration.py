import os
from jproperties import Properties
from dotenv import load_dotenv
from pathlib import Path

p = Path(__file__).resolve()


class Configuration:
    configs = Properties()
    with open('app-config.properties', 'rb') as config_file:
        configs.load(config_file)

    load_dotenv()

    dtrack_api_key = os.getenv('DTRACK_API_KEY')

    dtrack_api_url = configs.get('DTRACK_API_URL').data
