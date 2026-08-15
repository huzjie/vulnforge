"""Deliberately vulnerable example: unsafe deserialization (CWE-502)."""
import pickle


def load_session(data: bytes):
    """Deserialize an untrusted pickle blob — arbitrary code execution risk."""
    # vulnforge-static: deserialization
    return pickle.loads(data)


def load_yaml_payload(raw: str):
    """yaml.load with an unsafe Loader can construct arbitrary objects."""
    import yaml  # noqa: PLC0415 - kept local to mirror real-world patterns

    # vulnforge-static: deserialization
    return yaml.load(raw, Loader=yaml.Loader)
