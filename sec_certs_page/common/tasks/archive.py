import os
from pathlib import Path


class Archiver:  # pragma: no cover
    """
    Dataset
    =======

    ├── auxiliary_datasets          (not PP)
    │   ├── cpe_dataset.json
    │   ├── cve_dataset.json
    │   ├── cpe_match.json
    │   ├── algorithms.json         (only FIPS)
    │   ├── cc_scheme.json          (only CC)
    │   ├── protection_profiles     (only CC)
    │   │   ├── reports
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   ├── pps
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   └── dataset.json
    │   └── maintenances            (only CC)
    │       ├── certs
    │       │   ├── reports
    │       │   │   ├── pdf
    │       │   │   └── txt
    │       │   └── targets
    │       │       ├── pdf
    │       │       └── txt
    │       └── maintenance_updates.json
    ├── certs
    │   ├── reports                 (not FIPS)
    │   │   ├── pdf
    │   │   └── txt
    │   ├── targets                 (only CC and FIPS)
    │   │   ├── pdf
    │   │   └── txt
    │   ├── pps                     (only PP)
    │   │   ├── pdf
    │   │   └── txt
    │   └── certificates            (only CC)
    │       ├── pdf
    │       └── txt
    ├── reports                     (only PP)
    │   ├── pdf
    │   └── txt
    ├── pps                         (only PP)
    │   ├── pdf
    │   └── txt
    ├── pp.json                     (only PP)
    └── dataset.json
    """

    def map_artifact_dir(self, ids, fromdir, todir):
        for format in ("pdf", "txt"):
            src = Path(fromdir) / format
            dst = Path(todir) / format
            dst.mkdir(parents=True, exist_ok=True)
            for id in ids:
                name = f"{id}.{format}"
                from_file = src / name
                to_file = dst / name
                if from_file.exists():
                    os.symlink(from_file, to_file)

    def archive(self, ids, path, paths):
        pass
