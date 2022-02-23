try:
    import regex as re
except ModuleNotFoundError:
    import re  # type:ignore


def strip_config_header(config):
    """Normalize items that should not show up in IOS-XR compare_config."""
    config = re.sub(r"^Building config.*\n!! IOS.*", "", config, flags=re.M)
    config = config.strip()
    config = re.sub(r"^!!.*", "", config)
    config = re.sub(r"end$", "", config)
    return config.strip()
