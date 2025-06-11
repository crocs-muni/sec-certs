#!/usr/bin/env python3

if __name__ == "__main__":
    from tqdm import tqdm

    from sec_certs_page import app, mongo
    from sec_certs_page.common.webui import chat_full

    with app.app_context():
        # Iterate over all certificates in the 'cc' collection
        certs = list(mongo.db.cc.find({}, {"_id": 1, "heuristics": 1}))
        for cert in tqdm(certs, smoothing=0):
            hashid = cert["_id"]
            try:
                resp = chat_full(
                    queries=[
                        {
                            "role": "user",
                            "content": 'What is the certificate ID of this certificate? Respond only with the ID or "null" if it is unknown.',
                        }
                    ],
                    collection="cc",
                    hashid=hashid,
                    document="report",
                )
                json = resp.json()
                if "choices" not in json or not json["choices"]:
                    model_id = "error"
                else:
                    model_id = resp.json()["choices"][0]["message"]["content"]
            except ValueError as e:
                model_id = "error"
            our_id = cert["heuristics"]["cert_id"]
            print(f"{hashid},{our_id},{model_id}", flush=True)
