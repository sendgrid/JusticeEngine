import datetime
import fnmatch
import hashlib
import json
import time
import arrow
import os

from botocore.exceptions import ClientError
from boto.s3.key import Key
from security_monkey.alerters import custom_alerter
from security_monkey.common.sts_connect import connect
from security_monkey import app, db
from security_monkey.datastore import Account
from security_monkey.task_scheduler.alert_scheduler import schedule_krampus_alerts


class Notify:
    """Notification for resources outside of the Justice Engine."""
    KILL = 0
    DISABLE = 1

    def __init__(self):
        self.conn = None
        self.bucket = None
        self.key = None
        self.s3connect(os.getenv('AWS_ACCOUNT_NAME'), os.getenv('KRAMPUS_BUCKET'))

    def s3connect(self, account, bucket):
        """ s3connect will attempt to connect to an s3 bucket resource.
            If the resource does not exist it will attempt to create it
            :param account: string the aws account you are connecting to
            :param bucket: string the name of the bucket you wish to connect to
            :returns: Boolean of connection Status
        """
        self.conn = connect(
            account,
            's3'
        )

        if self.conn.lookup(bucket) is None:
            app.logger.debug("Bucket Does not exist. Creating one")
            self.bucket = self.conn.create_bucket(bucket)
        else:
            self.bucket = self.conn.get_bucket(bucket)

        self.key = Key(self.bucket)
        return True

    def get_s3_key(self, filename):
        """ Return the key contents for a specific s3 object
            :param filename: the file name of the s3 object
            :returns: data in the form of a Dict.
        """

        if self.bucket.lookup(filename) is None:
            self.key = self.bucket.new_key(filename)
            self.key.set_contents_from_string(json.dumps(json.loads('{}')))

        self.key.key = filename
        tmp = self.key.get_contents_as_string()
        return json.loads(tmp)

    def write_to_s3_object(self, filename, data):
        """ Write to s3
            :param filename: the s3 object file name
            :param data: string of data to be written to the object
            :returns: Boolean of writing success
        """
        try:
            self.key.key = filename
            self.key.set_contents_from_string(data)
            return True
        except ClientError as e:
            app.logger.critical(
                "Unable to push information back to s3. :: {0}".format(e))
            return False


class Jury():
    """ The Jury makes verdict based on evidence.
        The Jury class contains the methods used to convert
        items with issues into actionable jobs for Krampus to kill.
    """

    KILL_THRESHOLD = int(os.getenv('KILL_THRESHOLD'))
    DISABLE_THRESHOLD = int(os.getenv('DISABLE_THRESHOLD'))
    KILL_RESPONSE_DELTA = int(os.getenv('KILL_RESPONSE_DELTA'))
    DISABLE_RESPONSE_DELTA = int(os.getenv('DISABLE_RESPONSE_DELTA'))

    SECMONKEY_KRAMPUS_ITEM_MAP = {
        's3': ['s3'],
        'ebs': ['ebssnapshot', 'ebsvolume'],
        'ec2': ['ec2image', 'ec2instance'],
        'rds': [
            'rdsclustersnapshot', 'rdsdbcluster', 'rdsdbinstance',
            'rdssecuritygroup', 'rdssnapshot', 'rdssubnetgroup'],
        'iam': [
            'iamgroup', 'iamrole', 'iamssl',
            'iamuser', 'policy', 'samlprovider', 'keypair'],
        'security_group': ['securitygroup'],
        None: [
            'acm', 'sqs', 'cloudtrail', 'config',
            'configrecorder', 'connection', 'virtual_gateway',
            'elasticip', 'elasticsearchservice', 'elb', 'alb',
            'networkinterface', 'gcefirewallrule', 'gcenetwork',
            'gcsbucket', 'organization', 'repository', 'team',
            'glacier', 'kms', 'lambda', 'redshift', 'route53',
            'route53domains', 'ses', 'sns', 'dhcp', 'endpoint',
            'flowlog', 'natgateway', 'networkacl', 'peering',
            'routetable', 'subnet', 'vpc', 'vpn']}

    @staticmethod
    def calc_score(issues):
        """ Helper method for calculating scores after an audit.
            :param issues: list of the item issues to be turned into a score
            :return: int of the score based on the item's issues
        """
        score = 0
        for i in issues:
            if not i.justified:
                score += i.score
        return score

    @staticmethod
    def aws_object_type_mapper(aws_object_type):
        """ maps an aws_object_type from sec-monkey into an actionable type for krampus
            :param aws_object_type: string of the sec-monkey type
            :return: None
        """
        for key in SECMONKEY_KRAMPUS_ITEM_MAP:
            if aws_object_type in SECMONKEY_KRAMPUS_ITEM_MAP[key]:
                return key
        return None

    @staticmethod
    def s3_handler(item, issue):
        """ Append information required for handling s3 resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        jobs = []
        for grants in item.config['Grants']:
            jobs.append({
                "s3_principal": grants,
                "s3_permission": item.config['Grants'][grants]
            })
        return jobs

    @staticmethod
    def ebs_handler(item, issue):
        """ Append information required for handling ebs resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        return []

    @staticmethod
    def ec2_handler(item, issue):
        """ Append information required for handling ec2 resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        return []

    @staticmethod
    def rds_handler(item, issue):
        """ Append information required for handling rds resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        return []

    @staticmethod
    def iam_handler(item, issue):
        """ Append information required for handling iam resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        return []

    @staticmethod
    def sg_handler(item, issue):
        """ Append information required for handling security group resources
            :param item: the item to be handled
            :param issue: the issue to be handled
            :return: jobs based on this action
        """
        jobs = []

        # We don't want to do anything to issues that have a scoring of 0
        if issue.score == 0:
            return []

        if len(issue.notes.split(':')) != 2:
            return []

        rule_issue_id = issue.notes.split(':')[1]
        for rule in item.config.get('rules', []):
            if int(rule_issue_id) == int(rule.get("sg_index", -1)):
                jobs.append({
                    'cidr_ip': rule['cidr_ip'],
                    'from_port': rule['from_port'],
                    'to_port': rule['to_port'],
                    'proto': rule['ip_protocol'],
                    'direction': rule['rule_type']
                })
        return jobs

    @staticmethod
    def justice(score):
        """ Determine the action taken for a specific score
            :param score: int of the score for a specific item
            :return: string of the action to be taken
        """

        int_score = int(score)
        if int_score >= Jury.KILL_THRESHOLD:
            return "kill"
        if int_score >= Jury.DISABLE_THRESHOLD:
            return "disable"
        else:
            return "ignore"

    @staticmethod
    def should_be_actioned(score):
        """ Simple helper method to determine whether a job warrants action
            :param score: The int value
            :return: Boolean if job should be actioned.
        """
        if Jury.justice(score) == 'ignore':
            return False
        else:
            return True

    @staticmethod
    def get_current_time():
        """
            :return: float of current unix (seconds since epoch)
        """
        return time.time()

    @staticmethod
    def when_to_action(action):
        """ returns an int of when to action a specific resource based on the action
            :param action: String of the action decided
            :return: int, representing the unix time the action should occur.
        """
        if action == "kill":
            delta = Jury.KILL_RESPONSE_DELTA
            return Jury.get_current_time() + delta
        elif action == "disable":
            delta = Jury.DISABLE_RESPONSE_DELTA
            return Jury.get_current_time() + delta
        else:
            app.logger.error("when_to_action was invoked with an issue determined to be ignored.")
            raise ValueError("I can't serve Justice to those who have not committed injustice.")

    @staticmethod
    def gather_details_for_nuanced_actions(item, issues, object_type):
        """ Append actions related to specific issues. If we are not completely
        deleting a resource, we need more information for Krampus to action
        the job generated.

        i.e. If 3 rules in a security group need to be removed
        it's really 3 jobs that need to be added to the task file.
        :param item: the security monkey item that is to be used for gathering details
        :param issues: the secmonkey item called
        :param object_type: string of the aws resource type of the item
        :return jobs: a list of the jobs required to action the item.
        """

        if object_type is None:
            app.logger.info("Krampus does not have a handler for item type {0}".format(item.index))
            return {}

        type_handler = {
            's3': Jury.s3_handler,
            'ebs': Jury.ebs_handler,
            'ec2': Jury.ec2_handler,
            'rds': Jury.rds_handler,
            'iam': Jury.iam_handler,
            'security_group': Jury.sg_handler
        }

        resource_details = []

        for issue in item.audit_issues:
            extra_fields_by_aws_type = type_handler[object_type](item, issue)
            map(lambda x: (isinstance(x, dict)), extra_fields_by_aws_type)
            resource_details.extend(extra_fields_by_aws_type)

        return resource_details

    @staticmethod
    def get_case_insensitive_arn(item):
        """ get_case_insensitive_arn will return the arn if it exists within the provided item.
             there was some historical inconsistency here so this is just a safety class for older versions.
            param item: the secmonkey item containing the arn
            :return: string the arn result.
        """
        for key in ['arn', 'Arn']:
            if item.config.get(key, False):
                return item.config[key]
        app.logger.debug("Arn & arn not in config for {0} of type :: {1}".format(item.name, item.index))
        return None

    @staticmethod
    def get_account_of_item(item):
        """ returns the string of the account id hosting a specific item.
            This helps with S3 resources.
            :param item: the secmonkey item containing the arn
            :return: string account id result.
        """
        # base_arn = Jury.get_case_insensitive_arn(item)

        return str(db.session.query(Account.identifier).filter(
            Account.name == item.account).one()[0])

    @staticmethod
    def build_krampus_jobs_for_item(score, item, current_tasks, whitelist):
        """ build_krampus_jobs_for_item will create actionable jobs for krampus for a given aws resource.
             * if krampus is not going to delete the aws resource entirely, multiple jobs might be produced.
            :param score: int representing how 'bad' the resource is according to sec_monkey.
            :param item: the secmonkey item that needs jobs built
            :param current_tasks: dict of the current_tasks for krampus
            :param whitelist: dict of the krampus whitelist
            :return: list of the jobs for this item to be actioned by krampus.
        """
        arn = Jury.get_case_insensitive_arn(item)
        if arn is None:
            return []
        action = Jury.justice(score)

        issues = ""
        for issue in item.audit_issues:
            issues += "{0}::{1}\t{2}\n".format(issue.issue, issue.notes, issue.score)

        job = {
            'score': score,
            'action': action,
            'action_time': Jury.when_to_action(action),
            'audited_time': Jury.get_current_time(),
            'aws_resource_name': arn,
            'aws_account': Jury.get_account_of_item(item),
            'aws_region': item.region,
            'aws_object_type': Jury.aws_object_type_mapper(item.index),
            'human_readable_name': item.name,
            'secmonkey_id': item.db_item.id,
            'issues': issues,
        }

        # Only create jobs for the item if it's actually workable my Krampus
        if job['aws_resource_name'] is not None:
            if job['aws_object_type'] is None:
                job["unique_id"] = Jury.hash_job(job)
                job['is_whitelisted'] = True
                return [job]
            if job['action'] == 'disable':
                jobs = Jury.gather_details_for_nuanced_actions(
                    item,
                    job['issues'],
                    job['aws_object_type'])
                map(lambda x: x.update(job), jobs)
                map(lambda x: x.update({"unique_id": Jury.hash_job(job)}), jobs)
                for job in jobs:
                    job['is_whitelisted'] = Jury.whitelist_match(arn, whitelist) or Jury.convicted(job['unique_id'], current_tasks)
                return jobs
            else:
                job["unique_id"] = Jury.hash_job(job)
                job['is_whitelisted'] = Jury.whitelist_match(arn, whitelist) or Jury.convicted(job['unique_id'], current_tasks)
                return [job]
        return []

    @staticmethod
    def hash_job(job):
        """ hash_job creates a unique id to compare jobs.
            :param job: the job to be hashed
            :return: string hash representation uniquely identifying the job
        """
        hasher = hashlib.sha1()
        hasher.update(job['aws_resource_name'])
        hasher.update(str(job['score']))
        hasher.update(str(job['issues']))
        hasher.update(job['human_readable_name'])
        return hasher.hexdigest()

    @staticmethod
    def make_local_from_timestamp(timestamp, timezone='US/Mountain'):
        """ make_local_from_timestamp returns a local string representation of a unix timestamp
            :param timestamp: int unix timestamp
            :param timezone: string timezone matching a tzdb entry from iana
            :return: human readable string representing a local timestamp.
        """
        utc = arrow.get(timestamp)
        local_time = utc.to(timezone)
        return local_time.strftime('%a %I:%M %p')

    @staticmethod
    def make_utc_from_timestamp(timestamp):
        """ make_utc_from_timestamp returns a human readable string representing a UTC timestamp
            :param timestamp: timestamp in %Y-%m-%d %H:%M:%S
            :return: the unix timestamp as a datetime.datetime object
        """
        utc_time = datetime.datetime.utcfromtimestamp(timestamp)
        return utc_time.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def remove_if_in_current_tasks(arn, current_tasks):
        """ remove_if_in_current_tasks will remove a job if it exists within the current_tasks hash
            :param arn: string AWS Resource Name to check for in current_tasks
            :param current_tasks: dict of the current_tasks for krampus
        """
        for task in current_tasks:
            if task['aws_resource_name'] == arn:
                current_tasks.remove(task)

    @staticmethod
    def convicted(unique_id, current_tasks):
        """ convicted returns whether the current job in question has already been judged and needs to be actioned by krampus
            :param unique_id: string unique_id hash representation of a job
            :param current_tasks: dict of the current_tasks in krampus
            :return: boolean of whether the aws resource is to be actioned
        """
        for task in current_tasks:
            if task.get('unique_id', '') == unique_id:
                return True
        return False

    @staticmethod
    def whitelist_match(arn, whitelist):
        """ whitelist_match returns whether the whitelist has a fn-match of the arn in question.
            :param arn: string AWS Resource Name to check for in current_tasks
            :param whitelist: dict of the krampus whitelist
            :return: booelean of whether the arn is on the whitelist.
        """
        for pattern in whitelist.keys():
            if fnmatch.fnmatch(arn, pattern):
                return True
        return False


class Justice(object):
    """ The Judge that serves the Jury's verdict to Krampus.
        The Judge class faciliates the actions to be made for any set of issues
        found for a security_monkey item.
    """

    __metaclass__ = custom_alerter.AlerterType

    TASK_KEY = os.getenv('TASK_KEY')
    TASKS_FILE_NAME = os.getenv('TASKS_FILE_NAME')
    WHITELIST_KEY = os.getenv('WHITELIST_KEY')
    WHITELIST_FILE_NAME = os.getenv('WHITELIST_FILE_NAME')
    LOGS_FILE_NAME = "{0}.json".format(datetime.datetime.now().strftime('%Y-%m-%d'))

    def report_watcher_changes(self, watcher):
        """ report_watcher_changes must exist for report_auditor_changes to be
            invoked within the SecMonkey Auditor.

            This mimics the existing custom alerter documentation in SecurityMonkey:Develop
            as alerters can still work to perfom actions with watcher events as well as auditor events.
        """
        for item in watcher.changed_items:
            pass

    def report_auditor_changes(self, auditor):
        """ Primary Driver for the Justice Engine. We accumulate scores for a
            specific resource and determine if it needs to be actioned.

            Alerters only use the confirmed_new_issues and confirmed_fixed_issues
            item fields.

            The Game Plan:
            1. Gather the current tasks
            2. Remove the fixed items from the current tasks
            3. Calculate the current score from new and existing issues for all items
            4  If the current score is larger than or equal to the required thresholds we will update the tasks file.
        """

        notify = Notify()
        app.logger.debug("S3 Connection established.")

        app.logger.debug("Collecting existing items.")
        current_tasks = notify.get_s3_key(Justice.TASKS_FILE_NAME)
        if not current_tasks:
            current_tasks = {Justice.TASK_KEY: []}

        app.logger.debug("Collecting whitelisted items.")
        whitelist = notify.get_s3_key(Justice.WHITELIST_FILE_NAME)
        if not whitelist:
            whitelist = {Justice.WHITELIST_KEY: {}}

        app.logger.debug("Collecting log file \"{0}\"".format(Justice.LOGS_FILE_NAME))
        logs = notify.get_s3_key(Justice.LOGS_FILE_NAME)
        if not logs:
            logs = []

        new_tasks = []
        app.logger.debug("Beginning current audit")
        current_run_audit_time = Jury.get_current_time()
        for item in auditor.items:
            app.logger.debug("changes in {0}. Auditing".format(item.name))

            score = Jury.calc_score(item.audit_issues)

            # remove_if_in_current_tasks lets Krampus ignore those who have atoned
            Jury.remove_if_in_current_tasks(Jury.get_case_insensitive_arn(item), current_tasks[Justice.TASK_KEY])

            if Jury.should_be_actioned(score):
                jobs = Jury.build_krampus_jobs_for_item(score, item, current_tasks[Justice.TASK_KEY], whitelist)
                logs.extend(jobs)
                for job in jobs:
                    if not job['is_whitelisted']:
                        new_tasks.extend(jobs)

        new_tasks.extend(current_tasks[Justice.TASK_KEY])

        app.logger.debug("Tasks are updated locally.")
        app.logger.debug("{0} Tasks to be processed".format(
            len(new_tasks)))

        if new_tasks != []:
            app.logger.debug("Pushing tasks to s3.")
            notify.write_to_s3_object(Justice.TASKS_FILE_NAME, json.dumps({Justice.TASK_KEY: new_tasks}))

        if logs != []:
            app.logger.debug("Pushing logs to s3")
            notify.write_to_s3_object(Justice.LOGS_FILE_NAME, json.dumps(logs))

        app.logger.debug("Sending Alerts to Account Owners.")
        schedule_krampus_alerts.s(current_run_audit_time)
        app.logger.debug("Justice Engine Complete. Closing.")
