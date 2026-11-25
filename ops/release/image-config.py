"""Get the OCI config digest from the exact single-platform archive being scanned."""
import hashlib
import json
import re
import sys
import tarfile


def member(archive, path):
    entry = archive.getmember(path)
    if not entry.isfile() or not 0 < entry.size <= 4 * 1024 * 1024:
        raise ValueError("invalid metadata member")
    with archive.extractfile(entry) as stream:
        return stream.read()


def config_digest(path, tag):
    with tarfile.open(path) as archive:
        manifests = json.loads(member(archive, "manifest.json"))
        if len(manifests) != 1 or not {tag, "docker.io/library/" + tag}.intersection(manifests[0]["RepoTags"]):
            raise ValueError("unexpected image tag or platform count")
        config = manifests[0]["Config"]
        match = re.fullmatch(r"(?:blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json)", config)
        if not match:
            raise ValueError("invalid config reference")
        data = member(archive, config)
        digest = hashlib.sha256(data).hexdigest()
        meta = json.loads(data)
        if digest not in match.groups() or (meta["os"], meta["architecture"]) != ("linux", "amd64"):
            raise ValueError("invalid config identity")
        return "sha256:" + digest


if __name__ == "__main__":
    try:
        print(config_digest(sys.argv[1], sys.argv[2]))
    except (IndexError, KeyError, OSError, TypeError, ValueError, tarfile.TarError):
        sys.exit("Cannot verify the scanned Docker archive configuration")
