import sentry_sdk
from bs4 import BeautifulSoup
from bson import ObjectId
from celery.utils.log import get_task_logger
from sec_certs.dataset.common_criteria import CCDataset
from filtercss import filter_css, parse_css
from flask import current_app, render_template
from flask_mail import Message
from jsondiff import symbols

from .. import celery, mail, mongo
from ..common.diffs import has_symbols
from ..common.objformats import WorkingFormat, load
from ..common.tasks import Indexer, Updater, no_simultaneous_execution
from . import cc_categories

logger = get_task_logger(__name__)


def render_diff(cert, diff):
    if diff["type"] == "new":
        return render_template("cc/notifications/diff_new.html.jinja2", cert=diff["diff"])
    elif diff["type"] == "back":
        return render_template("cc/notifications/diff_back.html.jinja2", cert=cert)
    elif diff["type"] == "remove":
        return render_template("cc/notifications/diff_remove.html.jinja2", cert=cert)
    elif diff["type"] == "change":
        changes = []
        k2map = {
            "pdf_data": ("PDF extraction data", False),
            "state": ("state of the certificate object", False),
            "heuristics": ("computed heuristics", True),
            "maintenance_updates": ("Maintenance Updates of the certificate", True),
            "protection_profiles": ("Protection profiles of the certificate", True),
            "status": ("Status", False),
            "not_valid_after": ("Valid until date", False),
            "not_valid_before": ("Valid from date", False),
        }
        # This is so ugly but somewhat works.
        for k1, v1 in diff["diff"].items():
            if k1 == symbols.update:
                for k2, v2 in v1.items():
                    details = []
                    if has_symbols(v2):
                        for k3, v3 in v2.items():
                            if k3 == symbols.update:
                                if isinstance(v3, dict):
                                    for prop, val in v3.items():
                                        if has_symbols(val):
                                            detail = f"The {prop} property was updated."
                                            if symbols.insert in val:
                                                vjson = (
                                                    WorkingFormat(val[symbols.insert])
                                                    .to_storage_format()
                                                    .to_json_mapping()
                                                )
                                                detail += f" With the {vjson} values inserted."
                                            if symbols.discard in val:
                                                vjson = (
                                                    WorkingFormat(val[symbols.discard])
                                                    .to_storage_format()
                                                    .to_json_mapping()
                                                )
                                                detail += f" With the {vjson} values discarded."
                                            if symbols.update in val:
                                                vjson = (
                                                    WorkingFormat(val[symbols.update])
                                                    .to_storage_format()
                                                    .to_json_mapping()
                                                )
                                                detail += f" With the {vjson} data."
                                            if symbols.add in val:
                                                vjson = (
                                                    WorkingFormat(val[symbols.add])
                                                    .to_storage_format()
                                                    .to_json_mapping()
                                                )
                                                detail += f" With the {vjson} values added."
                                            details.append(detail)
                                        else:
                                            vjson = WorkingFormat(val).to_storage_format().to_json_mapping()
                                            details.append(f"The {prop} property was set to {vjson}.")
                            elif k3 == symbols.insert:
                                if has_symbols(v3):
                                    logger.error(f"Should not happen, ins: {k3}, {v3}")
                                else:
                                    vjson = WorkingFormat(v3).to_storage_format().to_json_mapping()
                                    details.append(f"The following values were inserted: {vjson}.")
                            elif k3 == symbols.delete:
                                vjson = WorkingFormat(v3).to_storage_format().to_json_mapping()
                                details.append(f"The following properties were deleted: {vjson}.")
                            else:
                                logger.error(f"Should not happen: {k3}, {v3}")
                    else:
                        vjson = WorkingFormat(v2).to_storage_format().to_json_mapping()
                        details.append(f"The new value is {vjson}.")
                    if k2 in k2map:
                        changes.append((k2map[k2], details))
                    else:
                        changes.append(((k2, False), details))
        return render_template("cc/notifications/diff_change.html.jinja2", cert=cert, changes=changes)


@celery.task(ignore_result=True)
def notify(run_id):
    run_oid = ObjectId(run_id)
    # Load up the diffs and certs
    change_diffs = {obj["dgst"]: load(obj) for obj in mongo.db.cc_diff.find({"run_id": run_oid, "type": "change"})}
    change_dgsts = list(change_diffs.keys())
    change_certs = {obj["dgst"]: load(obj) for obj in mongo.db.cc.find({"_id": {"$in": change_dgsts}})}

    # Render the individual diffs
    change_renders = {}
    for dgst in change_dgsts:
        change_renders[dgst] = render_diff(change_certs[dgst], change_diffs[dgst])

    # Group the subscriptions by email
    change_sub_emails = mongo.db.subs.find(
        {"certificate.hashid": {"$in": change_dgsts}, "confirmed": True}, {"email": 1}
    )
    emails = {sub["email"] for sub in change_sub_emails}

    # Load Bootstrap CSS
    with current_app.open_resource("static/lib/bootstrap.min.css", "r") as f:
        bootstrap_css = f.read()
    bootstrap_parsed = parse_css(bootstrap_css)

    # Get the run date
    run = mongo.db.cc_log.find_one({"_id": run_oid})
    run_date = run["start_time"].strftime("%d.%m.")

    # Go over the subscribed emails
    for email in emails:
        subscriptions = mongo.db.subs.find(
            {"certificate.hashid": {"$in": change_dgsts}, "confirmed": True, "email": email}
        )
        cards = []
        # Go over the subscriptions for a given email and accumulate its rendered diffs
        for sub in subscriptions:
            dgst = sub["certificate"]["hashid"]
            # diff = change_diffs[dgst]
            render = change_renders[dgst]
            if sub["updates"] == "vuln":
                # TODO: Figure out if this diff notification should be sent.
                pass
            cards.append(render)
        # Render diffs into body template
        email_core_html = render_template("notifications/email/notification_email.html.jinja2", cards=cards)
        # Filter out unused CSS rules
        cleaned_css = filter_css(bootstrap_parsed, email_core_html, minify=True)
        # Inject final CSS into html
        soup = BeautifulSoup(email_core_html, "lxml")
        css_tag = soup.new_tag("style")
        css_tag.insert(0, soup.new_string(cleaned_css))
        soup.find("meta").insert_after(css_tag)
        email_html = str(soup)
        # Send out the message
        msg = Message(f"Certificate changes from {run_date}", [email], html=email_html)
        mail.send(msg)


class CCIndexer(Indexer):  # pragma: no cover
    def __init__(self):
        self.dataset_path = current_app.config["DATASET_PATH_CC_DIR"]
        self.cert_schema = "cc"

    def create_document(self, dgst, document, cert, content):
        category_id = cc_categories[cert["category"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["name"],
            "document_type": document,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["status"],
            "content": content,
        }


@celery.task(ignore_result=True)
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = CCIndexer()
    indexer.reindex(to_reindex)


class CCUpdater(Updater):  # pragma: no cover
    def __init__(self):
        self.collection = "cc"
        self.diff_collection = "cc_diff"
        self.log_collection = "cc_log"
        self.skip_update = current_app.config["CC_SKIP_UPDATE"]
        self.dset_class = CCDataset

    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="cc.all", description="Get full CC dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="cc.get_certs", description="Get certs from web"):
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(op="cc.download_pdfs", description="Download pdfs"):
                    dset.download_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.convert_pdfs", description="Convert pdfs"):
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.analyze", description="Analyze certificates"):
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="cc.protection_profiles", description="Process protection profiles"):
                    dset.process_protection_profiles(update_json=False)
                with sentry_sdk.start_span(op="cc.maintenance_updates", description="Process maintenance updates"):
                    dset.process_maintenance_updates()
                with sentry_sdk.start_span(op="cc.protection_profiles", description="Process protection profiles"):
                    dset.process_protection_profiles()
                with sentry_sdk.start_span(op="cc.write_json", description="Write JSON"):
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="cc.move", description="Move files"):
                for cert in dset:
                    if cert.state.report_pdf_path and cert.state.report_pdf_path.exists():
                        dst = paths["report_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or dst.stat().st_size < cert.state.report_pdf_path.stat().st_size:
                            cert.state.report_pdf_path.replace(dst)
                    if cert.state.report_txt_path and cert.state.report_txt_path.exists():
                        dst = paths["report_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or dst.stat().st_size < cert.state.report_txt_path.stat().st_size:
                            cert.state.report_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "report"))
                    if cert.state.st_pdf_path and cert.state.st_pdf_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or dst.stat().st_size < cert.state.st_pdf_path.stat().st_size:
                            cert.state.st_pdf_path.replace(dst)
                    if cert.state.st_txt_path and cert.state.st_txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or dst.stat().st_size < cert.state.st_txt_path.stat().st_size:
                            cert.state.st_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "target"))
        return to_reindex

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.delay(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.delay(list(to_reindex))


@celery.task(ignore_result=True)
def update_data():  # pragma: no cover
    updater = CCUpdater()
    updater.update()
