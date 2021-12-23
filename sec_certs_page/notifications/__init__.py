from datetime import timedelta

from flask import Blueprint

from .. import celery

notifications = Blueprint("notify", __name__, url_prefix="/notify")

from .tasks import cleanup_subscriptions
from .views import *


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(timedelta(days=1), cleanup_subscriptions.s(), name="Cleanup unconfirmed subscriptions.")
