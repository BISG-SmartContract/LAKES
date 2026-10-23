from semantic_version import NpmSpec, Version


def match(versions, available):
    compatible = [
        value for value in available
        if all(Version(value) in NpmSpec(spec) for spec in versions)
    ]
    return max(compatible, key=Version) if compatible else None
