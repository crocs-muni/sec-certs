from datetime import timedelta
from urllib.parse import urlparse

import dramatiq
from bs4 import BeautifulSoup
from flask import current_app
from periodiq import cron

from . import sitemap, whoosh_index
from .cc.tasks import update_data as update_cc_data
from .common.tasks import task
from .fips.tasks import update_data as update_fips_data
from .fips.tasks import update_iut_data, update_mip_data
from .notifications.tasks import cleanup_subscriptions
from .pp.tasks import update_data as update_pp_data
from .vuln.tasks import update_cpe_data, update_cpe_match_data, update_cve_data


@dramatiq.actor(
    actor_name="run_updates_weekly", queue_name="updates", periodic=cron("0 12 * * 1")
)  # Every Monday at 12:00
def run_updates_weekly() -> None:  # pragma: no cover
    (
        update_cc_data.message_with_options(pipe_ignore=True)
        | update_fips_data.message_with_options(pipe_ignore=True)
        | update_pp_data.message_with_options(pipe_ignore=True)
    ).run()


@dramatiq.actor(
    actor_name="run_updates_daily", queue_name="updates", periodic=cron("0 0 * * *")
)  # Every day at midnight
def run_updates_daily() -> None:  # pragma: no cover
    (
        cleanup_subscriptions.message_with_options(pipe_ignore=True)
        | update_cve_data.message_with_options(pipe_ignore=True)
        | update_cpe_data.message_with_options(pipe_ignore=True)
        | update_cpe_match_data.message_with_options(pipe_ignore=True)
        | update_iut_data.message_with_options(pipe_ignore=True)
        | update_mip_data.message_with_options(pipe_ignore=True)
    ).run()


@dramatiq.actor(actor_name="sitemap_update", queue_name="default", time_limit=timedelta(hours=1).total_seconds() * 1000)
@task("sitemap_update")
def update_sitemap():
    # Just hack a request context, we do not need pretty much anything here.
    with current_app.test_request_context(""):
        smap = sitemap.sitemap()
        soup = BeautifulSoup(smap, "lxml")
        for loc in soup.find_all("loc"):
            location = str(loc.text)
            page = int("".join(filter(str.isdigit, location)))
            sitemap.page(page)


@dramatiq.actor(actor_name="optimize_index")
@task("optimize_index")
def optimize_index() -> None:
    whoosh_index.optimize()
