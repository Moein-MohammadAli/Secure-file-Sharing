from hashlib import blake2b
from core.models import AccessControl

def blake(data):
    """
    Function for get hash from a string
    :param data: string
    :return: byte array or hex
    """
    return blake2b(data.encode(), digest_size=32).hexdigest()


class BLP:
    @staticmethod
    def s_property(subject_level, object_level):
        '''
        S can read O iff S dominates O
        topest level is 1 and lowest level is 4
        '''
        return True if object_level >= subject_level else False

    @staticmethod
    def star_property(subject_level, object_level):
        '''
        S can write O iff O dominates S
        topest level is 1 and lowest level is 4
        '''
        return True if object_level <= subject_level else False


class Biba:
    @staticmethod
    def s_property(subject_level, object_level):
        '''
        S can read O iff integerity level of S is less than or equal to integrity level O
        topest level is 1 and lowest level is 4
        '''
        return True if object_level <= subject_level else False

    @staticmethod
    def star_property(subject_level, object_level):
        '''
        S can write O iff integerity level of O is less than or equal to integrity level S
        topest level is 1 and lowest level is 4
        '''
        return True if object_level >= subject_level else False


def has_access(subject, obj, permission):
    access = AccessControl.objects.get(subject=subject, obj=obj).access
    read_list, write_list, get_list = [1, 3, 5, 7], [2, 3, 6, 7], [4, 5, 6, 7]
    if permission == "Get":
        if (access in get_list):
            return True
    elif permission == "Write":
        if (access in write_list):
            return True
    elif permission == "Read":
        if (access in read_list):
            return True
    return False