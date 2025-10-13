"""This script extracts a base set of entries from a running up-to-date MongoDB instance to be used for tests."""

import subprocess

from pymongo import MongoClient
from pymongo.database import Database


def make_oid(id):
    return f'{{ "$oid": "{id}"}}'


def extract(collection, query):
    return subprocess.run(
        [
            "mongoexport",
            "-d",
            "seccerts",
            "-c",
            f"{collection}",
            "--query",
            query,
            "--jsonArray",
            "--pretty",
            "--out",
            f"{collection}.json",
        ]
    )


def prepare_base(db: Database, scheme, base_ids, old_ids):
    certs = list(db[f"{scheme}"].find({"dgst": {"$in": base_ids}}))
    if certs:
        print(f"Exporting {len(certs)} {scheme} certs")
        extract(f"{scheme}", '{"dgst": {"$in": [' + ", ".join(f'"{id}"' for id in base_ids) + "]}}")

    diffs = list(db[f"{scheme}_diff"].find({"dgst": {"$in": base_ids}}))
    if diffs:
        print(f"Exporting {len(diffs)} {scheme} diffs")
        extract(f"{scheme}_diff", '{"dgst": {"$in": [' + ", ".join(f'"{id}"' for id in base_ids) + "]}}")

    run_ids = set(d["run_id"] for d in diffs)
    if run_ids:
        print(f"Exporting {len(run_ids)} {scheme} runs")
        extract(f"{scheme}_log", '{"_id": {"$in": [' + ", ".join(f'{{ "$oid": "{id}"}}' for id in run_ids) + "]}}")

    olds = list(db[f"{scheme}_old"].find({"_id": {"$in": old_ids}}))
    if olds:
        print(f"Exporting {len(olds)} {scheme} old certs")
        extract(f"{scheme}_old", '{"_id": {"$in": [' + ", ".join(f'"{id}"' for id in old_ids) + "]}}")


def main():
    mongo = MongoClient("mongodb://localhost:27017/seccerts")

    fips_ids = [
        "03a3d955b8799a90",
        "d5b148567313dccf",
        "8fe1029e7f1d04f6",
        "0b8c4c7c81ac3255",
        "ae1f31e1ba28b07b",
        "226f76b55acb4970",
        "8527a891e2241369",
        "e629fa6598d73276",
        "cfe0815a32292cc3",
        "9fbba4a59829746f",
        "c7ce483fd1cc5fd4",
        "6b86b273ff34fce1",
        "3c365ff931ecb0e3",
    ]
    fips_old_ids = ["7d986a48cb5c4c8d3c62"]
    prepare_base(mongo["seccerts"], "fips", fips_ids, fips_old_ids)

    cc_ids = [
        "3d1b01ce576f605d",
        "44f677892bb84ce5",
        "f0c22e3e4abad667",
        "1412d1d9e0d553c1",
        "f1174ac2e100bc5c",
        "dba20653348d0d12",
        "eeff5b346faba43f",
        "663b9c1bde7447b3",
        "9628d00ce6f61640",
        "90969e38fd9b581f",
        "7bba408b3c99fd76",
        "6ca52f5450bedb2f",
    ]
    cc_old_ids = ["bf712f246f61e8678855", "4a1fa75170579066"]
    prepare_base(mongo["seccerts"], "cc", cc_ids, cc_old_ids)

    pp_ids = ["7b81fd67c02d34de", "55ed365edb2c317f", "7bf1cb12d183dcc0", "ecc28509c30de1a5", "477fa2c9a8069ca7"]
    prepare_base(mongo["seccerts"], "pp", pp_ids, [])

    fips_iut_ids = ["61f891ad4790725e9e9d4578"]
    extract("fips_iut", '{"_id": {"$in": [' + ", ".join(make_oid(id) for id in fips_iut_ids) + "]}}")
    fips_mip_ids = ["61f891ae309360b0d79d54ce"]
    extract("fips_mip", '{"_id": {"$in": [' + ", ".join(make_oid(id) for id in fips_mip_ids) + "]}}")

    cpe_ids = ["E94E1E84-F530-4D3E-963A-BB4E486BF3F7", "E1AD7F60-5BF9-4336-83CF-C7F381020437"]
    extract("cpe", '{"cpe_id": {"$in": [' + ", ".join(f'"{id}"' for id in cpe_ids) + "]}}")
    cve_ids = ["CVE-2019-15809", "CVE-2019-15807"]
    extract("cve", '{"_id": {"$in": [' + ", ".join(f'"{id}"' for id in cve_ids) + "]}}")


if __name__ == "__main__":
    main()
