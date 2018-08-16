import arrow
import calendar
import datetime
import os
import requests
import time

from security_monkey import app
from alerter_abs import AbstractAlerter


class HipchatHandler(AbstractAlerter):

    @staticmethod
    def make_local_from_timestamp(timestamp, timezone):
        """
        Make a human readable string converted into a local timestamp
        timezone names can be found here https://www.iana.org/time-zones
        :param timestamp: int unix timestamp
        :param timezone: string of the timezone to convert into
        :return: string of localized information
        """
        utc = arrow.get(timestamp)
        local_time = utc.to(timezone)
        return local_time.strftime('%a %I:%M %p')

    @staticmethod
    def make_utc_from_timestamp(timestamp):
        utc_time = datetime.datetime.utcfromtimestamp(timestamp)
        return utc_time.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def correct_indents(message):
        """
        Convert indents from standard tabs to spaces for Hipchat alerts
        :param message: string message to have intdents corrected
        :return: string message with corrected indents
        """
        return message.replace('\t', '    ')

    @staticmethod
    def format_item(item, timezone):
        """
        :param item: string item to formatted
        :param timezone: string name of local timezone
        :return: string of the item for Hipchat
        """

        item_url = "https://{0}/#/viewitem/{1}".format(os.getenv('SECMONKEY_HOSTNAME'), item['secmonkey_id'])
        color = 'yellow'
        note = ''

        if item['is_whitelisted']:
            note = "Krampus found the following issues with the AWS resource\n{0}\n{1}\n\t{2}More Info: {3}".format(
                item['human_readable_name'],
                item['aws_resource_name'],
                item['issues'].replace('\n', '\n\t'),
                item_url)
            color = 'yellow'
        elif item['action'] == 'kill' or item['action'] == 'disable':
            note = "Krampus is planning to {0}\n{1}\n{2}\nat {3} UTC\t{4} {5}\nfor the following issues:\n\t{6}Totaling a score of: {7}\nMore Info: {8}".format(
                item['action'],
                item['human_readable_name'],
                item['aws_resource_name'],
                HipchatHandler.make_utc_from_timestamp(item['action_time']),
                HipchatHandler.make_local_from_timestamp(item['action_time'], timezone),
                'MT',
                item['issues'].replace('\n', '\n\t'),
                item['score'],
                item_url)
            if item['action'] == 'kill':
                color = 'red'

        return color, note

    @staticmethod
    def send_hipchat_message(token, message, room, color='yellow'):
        """
        Sends a hipchat message.
        :param token: the bearer token for authenticating to hipchat
        :param message: the message to be sent
        :param room: the hipchat room to send to
        :param color: the color of the message in hipchat (yellow, green, red, purple, gray)
        :return: boolean of success
        """

        url = 'https://api.hipchat.com/v1/rooms/message'
        data = {
               'auth_token': token,
               'color': color,
               'from': 'Krampus',
               'message': message,
               'message_format': 'text',
               'notify': False,
               'room_id': room}

        rsp = requests.post(url, data=data)

        if rsp.headers.get('X-Ratelimit-Remaining') is not None:
            if int(rsp.headers.get('X-Ratelimit-Remaining')) <= 1:
                sleep_time = int(rsp.headers.get('X-Ratelimit-Reset')) - calendar.timegm(time.gmtime())
                print "Hit Hipchat Rate Limit. Sleeping {0}s".format(sleep_time + 1)
                time.sleep(sleep_time + 1)

        if str(rsp.status_code)[0] == '2':
            return True
        else:
            return False


    def alert(self, items, account_mapping):
        """
        Alert the team via HipChat that their resources are to be actioned
        :param items: the items to be messaged out
        :param account_mapping: the mapping of aws accounts to notificaiton channels
        :return: boolean of success or failure
        """

        token = os.getenv('HIPCHAT_KEY')
        timezone = os.getenv('LOCAL_TIMEZONE')
        default_room = os.getenv('HIPCHAT_DEFAULT_ROOM')

        # sort alerts by intended recipients and action type
        room_messages = {}
        room_messages[default_room] = {'kill': [], 'disable': [], 'whitelisted': []}

        for a_map in account_mapping:
            if not room_messages.get(a_map['HipChatRoom']):
                room_messages[a_map['HipChatRoom']] = {'kill': [], 'disable': [], 'whitelisted': []}

        for item in items:
            room_id = filter(lambda x: item['aws_account'] == x['AccountNumber'], account_mapping)
            if room_id and room_id[0]['HipChatRoom'] != 0:
                room_id = room_id[0]['HipChatRoom']
            else:
                room_id = default_room

            if item['is_whitelisted']:
                room_messages[room_id]['whitelisted'].append(HipchatHandler.format_item(item, timezone))
            else:
                room_messages[room_id].get(item['action'], []).append(HipchatHandler.format_item(item, timezone))

        app.logger.debug('Sending Hipchat Messages from Justice Engine Alerting')

        for room, alert in room_messages.iteritems():
            for action, messages in alert.iteritems():
                for message in messages:
                    HipchatHandler.send_hipchat_message(
                            token,
                            HipchatHandler.correct_indents('(krampus) {0}'.format(message[1])),
                            room,
                            message[0])

