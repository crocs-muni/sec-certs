import re

import pymongo
import sentry_sdk
from feedgen.feed import FeedGenerator
from flask import Response, url_for
from pymongo.collection import Collection
from pytz import timezone

from .diffs import DiffRenderer
from .objformats import load


class Feed:
    def __init__(self, renderer: DiffRenderer, logo_path: str, collection: Collection, diff_collection: Collection):
        self.renderer = renderer
        self.logo_path = logo_path
        self.collection = collection
        self.diff_collection = diff_collection

    def render(self, hashid: str) -> Response | None:
        raw_doc = self.collection.find_one({"_id": hashid})

        if raw_doc:
            tz = timezone("Europe/Prague")
            doc = load(raw_doc)
            feed_url = url_for(".entry_feed", hashid=hashid, _external=True)
            entry_url = url_for(".entry", hashid=hashid, _external=True)
            with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
                diffs = list(
                    map(load, self.diff_collection.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)]))
                )
                diff_renders = list(map(lambda x: self.renderer.render_diff(hashid, doc, x, linkback=True), diffs))
            fg = FeedGenerator()
            fg.id(feed_url)
            fg.title(re.sub("[^\u0020-\ud7ff\u0009\u000a\u000d\ue000-\ufffd\U00010000-\U0010ffff]+", "", doc["name"]))
            fg.author({"name": "sec-certs", "email": "webmaster@sec-certs.org"})
            fg.link({"href": entry_url, "rel": "alternate"})
            fg.link({"href": feed_url, "rel": "self"})
            fg.icon(url_for("static", filename="img/favicon.png", _external=True))
            fg.logo(url_for("static", filename=self.logo_path, _external=True))
            fg.language("en")
            last_update = None
            for diff, render in zip(diffs, diff_renders):
                date = tz.localize(diff["timestamp"])
                fe = fg.add_entry()
                fe.author({"name": "sec-certs", "email": "webmaster@sec-certs.org"})
                fe.title(
                    {
                        "back": "Certificate reappeared",
                        "change": "Certificate changed",
                        "new": "New certificate",
                        "remove": "Certificate removed",
                    }[diff["type"]]
                )
                fe.id(entry_url + str(diff["_id"]))
                stripped = re.sub(
                    "[^\u0020-\ud7ff\u0009\u000a\u000d\ue000-\ufffd\U00010000-\U0010ffff]+", "", str(render)
                )
                fe.content(stripped, type="html")
                fe.published(date)
                fe.updated(date)
                if last_update is None or date > last_update:
                    last_update = date

            fg.lastBuildDate(last_update)
            fg.updated(last_update)
            return Response(fg.atom_str(pretty=True), mimetype="application/atom+xml")
        else:
            return None
