import json
from pathlib import Path


def load_threat_data(file_path):
    """
    Load and validate threat intelligence records from a JSON file.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as file:
            records = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON file: {error}") from error

    if not isinstance(records, list):
        raise ValueError("Expected a JSON list containing threat records.")

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(
                f"Invalid record at position {index}: expected a dictionary."
            )

    return records