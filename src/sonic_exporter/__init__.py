import logging
import logging.config
from pathlib import Path
import yaml

base_path = Path(__file__).parent
file_path = (base_path / "./config/logging.yml").resolve()
with open(file_path, "r") as stream:
    config = yaml.load(stream, Loader=yaml.FullLoader)
logging.config.dictConfig(config)
