#!/usr/bin/env python3

import click
from tqdm import tqdm

from sec_certs_page import app, mongo
from sec_certs_page.common.webui import chat_full


@click.command()
@click.option(
    "--model",
    type=click.Choice(
        [
            "llama-4-scout-17b-16e-instruct",
            "gpt-oss-120b",
            "deepseek-r1",
        ]
    ),
    default="llama-4-scout-17b-16e-instruct",
    show_default=True,
    help="Model to use for inference.",
)
@click.option(
    "--context",
    "document",
    type=click.Choice(["report", "target", "both"]),
    default="both",
    show_default=True,
    help="Document context to use.",
)
def main(model: str, document: str):
    """Iterate over CC certificates and query the model for the certificate ID.

    This replaces the previous ad-hoc script with a Click CLI exposing
    --model and --context options.
    """
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
                    model=model,
                    collection="cc",
                    hashid=hashid,
                    document=document,
                )
                j = resp.json()
                if "choices" not in j or not j["choices"]:
                    model_id = "error"
                else:
                    model_id = j["choices"][0]["message"]["content"]
            except ValueError:
                model_id = "error"
            our_id = cert["heuristics"]["cert_id"]
            print(f"{hashid},{our_id},{model_id}", flush=True)


if __name__ == "__main__":
    main()
