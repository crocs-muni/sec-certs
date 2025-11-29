from bs4 import BeautifulSoup
from bson import ObjectId
from filtercss import filter_css, parse_css
from flask import current_app, render_template, url_for
from jsondiff import symbols

from ... import mail, mongo
from ...user import User
from ..diffs import DiffRenderer
from ..mail import Message
from ..objformats import load


class Notifier(DiffRenderer):
    """
    Notification handler for certificate changes.

    Should have the `DiffRenderer` attributes filled in when subclassed.
    """

    def notify(self, run_id: str):
        run_oid = ObjectId(run_id)

        # Load diffs, certs and render them
        objs = self._load_diffs_and_certs(run_oid)
        change_renders = self._render_many(
            objs["change_dgsts"], objs["change_certs"], objs["change_diffs"], linkback=True, name=True
        )
        new_renders = self._render_many(objs["new_dgsts"], objs["new_certs"], objs["new_diffs"], linkback=True)

        # Group the subscriptions by username
        usernames = self._collect_usernames(objs["change_dgsts"], objs["new_dgsts"])
        if not usernames:
            return

        # Prepare CSS and run date
        bootstrap_parsed = self._load_bootstrap_parsed()
        run_date = self._get_run_date(run_oid)

        # Send notifications per user
        for username in usernames:
            cards, urls, some_changes, some_new = self._gather_user_cards(
                username, objs["change_dgsts"], objs["change_diffs"], change_renders, new_renders
            )
            if not some_changes and not some_new:
                continue

            subject = f"Certificate changes from {run_date} | sec-certs.org"
            email_html, email_plain = self._compose_email(cards, urls, some_changes, some_new, subject, bootstrap_parsed)
            user = User.get(username=username)
            msg = Message(subject, [user.email], body=email_plain, html=email_html)
            mail.send(msg)

    # --- Private helpers ---

    def _load_diffs_and_certs(self, run_oid: ObjectId):
        # Load up the diffs and certs
        change_diffs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.diff_collection].find({"run_id": run_oid, "type": "change"})
        }
        change_dgsts = list(change_diffs.keys())
        change_certs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.collection].find({"_id": {"$in": change_dgsts}})
        }
        new_diffs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.diff_collection].find({"run_id": run_oid, "type": "new"})
        }
        new_dgsts = list(new_diffs.keys())
        new_certs = {obj["dgst"]: load(obj) for obj in mongo.db[self.collection].find({"_id": {"$in": new_dgsts}})}
        return {
            "change_diffs": change_diffs,
            "change_certs": change_certs,
            "change_dgsts": change_dgsts,
            "new_diffs": new_diffs,
            "new_certs": new_certs,
            "new_dgsts": new_dgsts,
        }

    def _render_many(self, dgst_list, certs_dict, diffs_dict, linkback=False, name=False):
        renders = {}
        for dgst in dgst_list:
            renders[dgst] = self.render_diff(dgst, certs_dict[dgst], diffs_dict[dgst], linkback=linkback, name=name)
        return renders

    def _collect_usernames(self, change_dgsts, new_dgsts):
        change_sub_emails = mongo.db.subs.find(
            {"certificate.hashid": {"$in": change_dgsts}, "certificate.type": self.collection},
        )
        new_sub_emails = mongo.db.subs.find({"updates": "new", "which": self.collection})
        return {sub["username"] for sub in change_sub_emails} | {sub["username"] for sub in new_sub_emails}

    def _load_bootstrap_parsed(self):
        with current_app.open_resource("static/lib/bootstrap.min.css", "r") as f:
            bootstrap_css = f.read()
        return parse_css(bootstrap_css)

    def _get_run_date(self, run_oid: ObjectId):
        run = mongo.db[self.log_collection].find_one({"_id": run_oid})
        return run["start_time"].strftime("%d.%m.")

    def _gather_user_cards(self, username, change_dgsts, change_diffs, change_renders, new_renders):
        cards = []
        urls = []
        some_changes = False

        # Subscriptions for changes
        subscriptions = list(
            mongo.db.subs.find(
                {
                    "certificate.hashid": {"$in": change_dgsts},
                    "username": username,
                    "certificate.type": self.collection,
                }
            )
        )
        if subscriptions:
            for sub in subscriptions:
                if sub["type"] != "changes":
                    continue
                dgst = sub["certificate"]["hashid"]
                diff = change_diffs[dgst]
                render = change_renders[dgst]
                if sub.get("updates") == "vuln":
                    # This is a vuln-only subscription: check if heuristics contain related_cves
                    h = diff["diff"].get(symbols.update, {}).get("heuristics")
                    if h:
                        for action, val in h.items():
                            if "related_cves" in val:
                                break
                        else:
                            # no related_cves found in heuristics -> skip
                            continue
                cards.append(render)
                urls.append(url_for(f"{self.collection}.entry", hashid=dgst, _external=True))
                some_changes = True

        # Subscriptions for new certs
        some_new = False
        new_subscriptions = list(mongo.db.subs.find({"username": username, "type": "new", "which": self.collection}))
        if new_subscriptions:
            for dgst, render in new_renders.items():
                cards.append(render)
                urls.append(url_for(f"{self.collection}.entry", hashid=dgst, _external=True))
                some_new = True

        return cards, urls, some_changes, some_new

    def _compose_email(self, cards, urls, some_changes, some_new, subject, bootstrap_parsed):
        # Render html body using jinja template
        email_core_html = render_template(
            "notifications/email/notification_email.html.jinja2",
            cards=cards,
            changes=some_changes,
            new=some_new,
            subject=subject,
        )
        # Filter out unused CSS rules
        cleaned_css = filter_css(bootstrap_parsed, email_core_html)
        # Inject final CSS into html
        soup = BeautifulSoup(email_core_html, "lxml")
        css_tag = soup.new_tag("style")
        css_tag.insert(0, soup.new_string(cleaned_css))
        soup.find("meta").insert_after(css_tag)
        email_html = soup.prettify(formatter="html")

        # Render plaintext part
        email_plain = render_template(
            "notifications/email/notification_email.txt.jinja2",
            urls=urls,
            changes=some_changes,
            new=some_new,
            subject=subject,
        )
        return email_html, email_plain
