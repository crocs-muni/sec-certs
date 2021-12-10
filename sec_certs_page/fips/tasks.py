from .. import celery


@celery.task(ignore_result=True)
def update_data():
    pass
