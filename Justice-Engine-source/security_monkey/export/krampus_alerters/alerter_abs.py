from abc import abstractmethod, ABCMeta


class AbstractAlerter(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def alert(self, items, account_mapping):
        """
        :param items: the items to be messaged out
        :param account_mapping: the mapping of aws accounts to notificaiton channels
        :return: boolean of success or failure
        """
        raise NotImplementedError("Alerters must have an action method implemented.")

