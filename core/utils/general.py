from hashlib import blake2b

def blake(data):
    """
    Function for get hash from a string
    :param data: string
    :return: byte array or hex
    """
    return blake2b(data, digest_size=32).hexdigest()


class BLP:
    @staticmethod
    def s_property(subject_level, object_level):
        '''
        S can read O iff S dominates O
        '''
        return True if object_level <= subject_level else False

    @staticmethod
    def star_property(subject_level, object_level):
        '''
        S can write O iff O dominates S 
        '''
        return True if object_level >= subject_level else False


class Biba:
    @staticmethod
    def s_property(subject_level, object_level):
        '''
        S can read O iff S dominates O
        '''
        return True if object_level >= subject_level else False

    @staticmethod
    def star_property(subject_level, object_level):
        '''
        S can write O iff O dominates S 
        '''
        return True if object_level <= subject_level else False

