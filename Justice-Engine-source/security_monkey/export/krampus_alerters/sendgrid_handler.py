import os
import datetime
import arrow
import sendgrid

from security_monkey import app
from alerter_abs import AbstractAlerter


class SendgridHandler(AbstractAlerter):
    @staticmethod
    def make_local_from_timestamp(timestamp, timezone):
        """
        Make a human readable string converted into a local timestamp
        :param timestamp: int unix timestamp
        :param timezone: string of the timezone to convert into
        :return: string of localized information
        """
        utc = arrow.get(timestamp)
        local_time = utc.to(timezone)
        return local_time.strftime('%a %I:%M %p')

    @staticmethod
    def make_utc_from_timestamp(timestamp):
        """
        Make a human readable UTC string from the current timestamp
        :param timestamp: int unix timestamp
        :return: string of timestamp converted into human readable utc
        """
        utc_time = datetime.datetime.utcfromtimestamp(timestamp)
        return utc_time.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def format_item_for_email(item, timezone):
        """
        Format a specific item into text for an email
        :param item:
        :return:
        """
        item_url = "https://{0}/#/viewitem/{1}".format(os.getenv('SECMONKEY_HOST'), item['secmonkey_id'])
        note = None

        if item['is_whitelisted']:
            note = "Krampus found the following issues with the AWS resource >> {0} <<\n{1}\n{2}More Info: {3}".format(
                item['human_readable_name'],
                item['aws_resource_name'],
                item['issues'],
                item_url)
        elif item['action'] == 'kill' or item['action'] == 'disable':
            note = "{0}\n{1}\nat {2} UTC    {3} {4}\nfor the following issues:\n{5}Totaling a score of: {6}\nMore Info: {7}".format(
                item['human_readable_name'],
                item['aws_resource_name'],
                SendgridHandler.make_utc_from_timestamp(item['action_time']),
                SendgridHandler.make_local_from_timestamp(item['action_time'], timezone),
                'MT',
                item['issues'].replace('\t', '    '),
                item['score'],
                item_url)

        return note

    @staticmethod
    def create_message(email_recipients, aggregate):
        """
        Make a list of emails to be sent.
        :param email_recipients: dict of message recipients mapped to messages
        :param aggregate: boolean of whether the messages should be aggregated together
        :return: (string, string) email, message tuple
        """
        new_line = '__________________________________________________'

        if aggregate:
            for recipient, messages in email_recipients.iteritems():
                message = ''
                if len(messages['kill']):
                    message += "ITEMS TO BE KILLED:\n{0}\n{1}\n\n".format(
                        new_line,
                        '\n{0}\n'.format(new_line).join(email_recipients[recipient]['kill']))
                if len(messages['disable']):
                    message += "ITEMS TO BE DISABLED:\n{0}\n{1}\n\n".format(
                        new_line,
                        '\n{0}\n'.format(new_line).join(email_recipients[recipient]['disable']))
                if len(messages['whitelisted']):
                    message += "ITEMS WITH ISSUES TO ADDRESS:\n{0}\n{1}\n\n".format(
                        new_line,
                        '\n{0}\n'.format(new_line).join(email_recipients[recipient]['whitelisted']))
                return [(recipient, SendgridHandler.double_newlines(message))]

        else:
            emails = []
            for recipient, messages in email_recipients.iteritems():
                for message in messages['kill']:
                    emails.append((recipient, "Krampus is planning to KILL {0}".format(SendgridHandler.double_newlines(message))))
                for message in messages['disable']:
                    emails.append((recipient, "Krampus is planning to DISABLE {0}".format(SendgridHandler.double_newlines(message))))
                for message in messages['whitelisted']:
                    emails.append((recipient, "Krampus found issues with {0}".format(SendgridHandler.double_newlines(message))))
            return emails

    @staticmethod
    def double_newlines(message):
        """
        This is because the text/plain MIME can be troublesome with newlines.
        :param message: email message that needs to have it's newlines doubled
        :return: the message with newlines doubled
        """
        return message.replace('\n', '\n\n')

    @staticmethod
    def send_email(sender, recipient, message, sg):
        """
        Sends and email with information related to the items to be actioned
        :param sender: string Who this email is from
        :param recipient: string Who this email is going to
        :param message: string The message to be delivered
        :param sg: Sendgrid instance
        :return: boolean of success.
        """
        data = {
            "personalizations": [
                {
                    "to": [
                        {
                            "email": recipient
                        }
                    ],
                    "subject": "Your Cloud Resources Require Attention."
                }
            ],
            "from": {
                "email": sender
            },

            "content": [
                {
                    "type": "text/plain",
                    "value": message
                }
            ]
        }
        response = sg.client.mail.send.post(request_body=data)

        if str(response)[0] == '2':
            app.logger.debug("Email sent to {0}".format(recipient))
            return True
        else:
            app.logger.debug("Email failed to send to {0}".format(recipient))
            return False

    def alert(self, items, account_mapping):
        """
        :param items: the items to be messaged out
        :param account_mapping: the mapping of aws accounts to notificaiton channels
        :return: boolean of success or failure
        """

        timezone = os.getenv('LOCAL_TIMEZONE')
        default_recipient = os.getenv('SENDGRID_DEFAULT_RECIPIENT')
        sg = sendgrid.SendGridAPIClient(apikey=os.getenv('SENDGRID_API_KEY'))
        sender = os.getenv('SENDGRID_SENDER_ADDRESS')

        # sort alerts by intended recipients and action type
        email_recipients = {}
        email_recipients[default_recipient] = {'kill': [], 'disable': [], 'whitelisted': []}

        for a_map in account_mapping:
            if not email_recipients.get(a_map['email']):
                email_recipients[a_map['email']] = {'kill': [], 'disable': [], 'whitelisted': []}

        for item in items:
            email = filter(lambda x: item['aws_account'] == x['aws_account'], account_mapping)
            if email:
                email = email[0]['email']
            else:
                email = default_recipient

            # convert messages into email strings
            if item['is_whitelisted']:
                email_recipients[email]['whitelisted'].append(SendgridHandler.format_item_for_email(item, timezone))
            else:
                email_recipients[email][item['action']].append(SendgridHandler.format_item_for_email(item, timezone))

        # create email messages from email strings and aggregation preference
        emails = SendgridHandler.create_message(email_recipients, aggregate)

        for email in emails:
            SendgridHandler.send_email(sender, email[0], email[1], sg)
