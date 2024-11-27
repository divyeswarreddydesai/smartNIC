# log.py
from framework.logging.log_config import logger

def ERROR(message):
    """Logs an error message."""
    logger.error(message,stacklevel=2)

def INFO(message):
    """Logs an informational message."""
    logger.info(message,stacklevel=2)

def DEBUG(message):
    """Logs a debug message."""
    logger.debug(message,stacklevel=2)
def RESULT(message):
    """Logs a result message."""
    logger.info("-"*50,stacklevel=2)
    logger.info(message,stacklevel=2)
    logger.info("-"*50,stacklevel=2)
def WARN(message):
    """Logs a warning message."""
    logger.warning(message,stacklevel=2)