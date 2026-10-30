import json
import pytest

from src.ingestion import load_threat_data


def test_load_valid_json_file(tmp_path):
    test_data = [
        {
            "ip_address": "192.0.2.10",
            "port": 443,
            "status": "online",
            "malware": "TestMalware"
        }
    ]

    file_path = tmp_path / "valid_data.json"
    file_path.write_text(json.dumps(test_data), encoding="utf-8")

    records = load_threat_data(file_path)

    assert len(records) == 1
    assert records[0]["ip_address"] == "192.0.2.10"


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_threat_data("data/nonexistent.json")


def test_invalid_json_file(tmp_path):
    file_path = tmp_path / "invalid.json"
    file_path.write_text("{invalid json}", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON file"):
        load_threat_data(file_path)


def test_json_must_be_a_list(tmp_path):
    file_path = tmp_path / "dictionary.json"
    file_path.write_text(
        json.dumps({"ip_address": "192.0.2.10"}),
        encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Expected a JSON list"):
        load_threat_data(file_path)


def test_records_must_be_dictionaries(tmp_path):
    file_path = tmp_path / "wrong_record.json"
    file_path.write_text(json.dumps(["invalid record"]), encoding="utf-8")

    with pytest.raises(ValueError, match="expected a dictionary"):
        load_threat_data(file_path)