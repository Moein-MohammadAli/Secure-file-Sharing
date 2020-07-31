from hashlib import blake2b

def blake(data):
    """
    Function for get hash from a string
    :param data: string
    :return: byte array or hex
    """
    return blake2b(data, digest_size=32).hexdigest()