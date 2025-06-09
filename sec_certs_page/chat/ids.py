#!/usr/bin/env python3

if __name__ == "__main__":
    from tqdm import tqdm

    from sec_certs_page import app, mongo
    from sec_certs_page.common.webui import chat_about, file_map

    with app.app_context():
        # Prepare the file map for resolving files
        file_map()
        # Iterate over all certificates in the 'cc' collection
        certs = list(mongo.db.cc.find({}, {"_id": 1, "heuristics": 1}))
        for cert in tqdm(certs, smoothing=0):
            hashid = cert["_id"]
            resp = chat_about(
                query=[
                    {
                        "role": "user",
                        "content": 'What is the certificate ID of this certificate? Respond only with the ID or "null" if it is unknown.',
                    }
                ],
                collection="cc",
                hashid=hashid,
                about="entry",
            )
            model_id = resp.json()["choices"][0]["message"]["content"]
            our_id = cert["heuristics"]["cert_id"]
            print(f"{hashid},{our_id},{model_id}", flush=True)
