import datetime
import json
import os

from security_monkey import app
from security_monkey.task_scheduler.util import CELERY
from security_monkey.common.sts_connect import connect
from security_monkey.export.krampus_alerters import *
from boto.s3.key import Key


def s3connect(account, bucket):
    """ s3connect will attempt to connect to an s3 bucket resource.
        If the resource does not exist it will attempt to create it
        :param account: string the aws account you are connecting to
        :param bucket: string the name of the bucket you wish to connect to
        :returns: Boolean of connection Status
    """
    conn = connect(
        account,
        's3'
    )

    if conn.lookup(bucket) is None:
        bucket = conn.create_bucket(bucket)
    else:
        bucket = conn.get_bucket(bucket)

    key = Key(bucket)
    return conn, bucket, key


def get_s3_key(conn, bucket, key, filename):
    """ Return the key contents for a specific s3 object
        :param bucket: the bucket to connect to
        :param key: the key of the bucket object
        :param filename: the file name of the s3 object
        :returns: data in the form of a string or Dict.
    """

    if bucket.lookup(filename) is None:
        newkey = self.bucket.new_key(filename)
        newkey.set_contents_from_string(json.dumps(json.loads('{}')))

    key.key = filename
    tmp = key.get_contents_as_string()
    return json.loads(tmp)


@CELERY.task(bind=True, max_retries=3)
def schedule_krampus_alerts(self, actioned_time):
    """ Alert accounts about the actions that will be
        made to their resources based on the Justice Engine
        :param actioned_time: the time that these accounts were found by the Justice Engine
        :return: String of the workers completed
    """

    conn, bucket, key = s3connect(os.getenv('AWS_ACCOUNT_NAME'), os.getenv('KRAMPUS_BUCKET'))
    filename = "{0}.json".format(datetime.datetime.now().strftime('%Y-%m-%d'))
    items = get_s3_key(conn, bucket, key, filename)

    if items == {}:
        app.logger.info("No items to alert on. Closing.")
        return "Unable to notify with no items passed to the alert_scheduler"

    recent_jobs = filter(lambda item: item['audited_time'] > actioned_time, items)
    if recent_jobs == []:
        app.logger.info("No new items to alert on. Closing.")
        return "No new jobs passed to alerters"

    account_mapping = get_s3_key(conn, bucket, key, os.getenv('MAPPING_FILE_NAME'))
    if items == {}:
        app.logger.info("No information in Justice Engine mapping file. All alerts going to default rooms.")

    # The following array contains the class names that you intend to alert with.
    enabled_workers = os.getenv('ENABLED_ALERT_HANLDERS').split(',')

    actioned = []
    for worker in enabled_workers:
        if worker in globals().keys():
            invoked_worker = globals()[worker]()
            invoked_worker.alert(recent_jobs, account_mapping)
            actioned.append(worker)
        else:
            app.logger.error('Can\'t call {0} as method does not exist'.format(worker))
    return "worked: {0}".format(", ".join(x for x in actioned))
