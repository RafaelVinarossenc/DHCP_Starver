import random
import string
import threading
import logging
from logging.handlers import TimedRotatingFileHandler

# Define a semaphore for .log/.json file access without collision
file_semaphore = threading.Semaphore()

def setup_logging(log_file):
    """
    Set up logging with rotation policy.
    This function initializes the logger and sets up the file handler.
    
    :param log_file: Path to the log file
    """
    handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7, encoding='utf-8', utc=True)
    handler.suffix = "%Y-%m-%d"
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    # Set up scapy logger to error
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def write_to_log(message):
    """
    Write message to log file.
    This function uses the semaphore to ensure that log writes do not collide.
    
    :param message: The message to write to the log
    """
    with file_semaphore:
        logger = logging.getLogger()
        logger.info(message)


def get_random_mac():
    """
    Returns a string with a "random" MAC address
    """
    mac = "34:" # Our bogus MAC addresses starts with 34 to make it easier to track/debug
    for i in range(10):
        num = random.randint(0, 15)
        if num < 10:
            num = chr(48 + num)
        else:
            num = chr(87 + num)
        mac += num
        if i % 2 == 1:
            mac += ":"
    return mac[:-1]


def get_random_hostname():
    """
    Returns a random string like "DESKTOP-XXXXXXX"
    """
    chars = string.ascii_uppercase + string.digits
    random_string = ''.join(random.choice(chars) for _ in range(7))
    return "DESKTOP-" + random_string
