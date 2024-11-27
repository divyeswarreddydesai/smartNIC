# log_config.py
import logging
import os
from datetime import datetime
# Create a custom logger

def setup_logger(debug=False):
    # Create a custom logger
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = os.path.join(os.environ.get('PYTHONPATH', ''), f'logs/{timestamp}.log')
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    logger = logging.getLogger('nu_logger')
    
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # Create a custom logger
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = os.path.join(os.environ.get('PYTHONPATH', ''), f'logs/{timestamp}.log')
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    logging.basicConfig(filename=file_path, encoding='utf-8', level=logging.DEBUG if debug else logging.INFO)
    
    # Set the default logging level
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Create formatters and add them to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handlers to the logger
    logger.addHandler(console_handler)
    
    return logger

# Initialize the logger with default level INFO
logger = setup_logger()