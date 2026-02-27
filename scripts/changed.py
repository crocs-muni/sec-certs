#!/usr/bin/env python3


def has_key(d, *key):
    for k in key:
        if k not in d:
            return False
        d = d[k]
    return True


if __name__ == "__main__":
    import argparse

    import pymongo

    # This script is used to find certificates that have had their PDF hashes change across diffs, and to count how many unique PDF hashes each certificate has had across all diffs.
    # It has two modes: "changed" and "count". In "changed" mode, it prints out each certificate that has had a PDF hash change, along with the document type (cert, report, or st), the timestamp of the change, and the previous and current hashes. In "count" mode, it prints out each certificate that has had more than one unique PDF hash across all diffs, along with the number of unique hashes for each document type.
    parser = argparse.ArgumentParser(description="Find certificates with PDF hash changes across diffs.")
    parser.add_argument(
        "mode",
        choices=["changed", "count"],
        help="Mode of operation: 'changed' to print changes, 'count' to count unique hashes.",
    )
    args = parser.parse_args()

    from sec_certs_page import app, mongo
    from sec_certs_page.common.diffs import apply_explicit_diff
    from sec_certs_page.common.objformats import load

    cc = mongo.db.cc
    cc_diff = mongo.db.cc_diff
    with app.app_context():
        for cert in cc.find({}, {"_id": 1}):
            hashid = cert["_id"]
            new_diff = mongo.db.cc_diff.find_one({"dgst": hashid, "type": "new"})
            diffs = cc_diff.find({"dgst": hashid, "type": "change"}).sort([("timestamp", pymongo.ASCENDING)])
            if not diffs:
                continue
            current = load(new_diff["diff"])
            hashes: dict[str, set[str]] = {"cert": set(), "report": set(), "st": set()}
            hashes["cert"].add(current["state"]["cert"]["pdf_hash"])
            hashes["report"].add(current["state"]["report"]["pdf_hash"])
            hashes["st"].add(current["state"]["st"]["pdf_hash"])
            for diff in diffs:
                previous = current
                current = apply_explicit_diff(current, load(diff["diff"]))
                hashes["cert"].add(current["state"]["cert"]["pdf_hash"])
                hashes["report"].add(current["state"]["report"]["pdf_hash"])
                hashes["st"].add(current["state"]["st"]["pdf_hash"])
                for doc in ("cert", "report", "st"):
                    if has_key(diff["diff"], "__update__", "state", "__update__", doc, "__update__", "pdf_hash"):
                        prev_hash = previous["state"][doc]["pdf_hash"]
                        curr_hash = current["state"][doc]["pdf_hash"]
                        if prev_hash is not None and curr_hash is not None and prev_hash != curr_hash:
                            if args.mode == "changed":
                                print(hashid, doc, diff["timestamp"], prev_hash, curr_hash, sep=",")
            hashes["cert"] = {h for h in hashes["cert"] if h is not None}
            hashes["report"] = {h for h in hashes["report"] if h is not None}
            hashes["st"] = {h for h in hashes["st"] if h is not None}
            if len(hashes["cert"]) > 1 or len(hashes["report"]) > 1 or len(hashes["st"]) > 1:
                if args.mode == "count":
                    print(hashid, len(hashes["cert"]), len(hashes["report"]), len(hashes["st"]), sep=",")
