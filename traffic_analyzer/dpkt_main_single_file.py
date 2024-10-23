import os
import argparse
import logging
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-sp","--src_path",type=str,default=None)
    parser.add_argument("-dp","--dst_path",type=str,default=None)
    parser.add_argument('-cp','--corporation',type=str,default=None,help="tt or wxy")
    options = parser.parse_args()
    if not os.path.isdir(os.path.join(options.dst_path, "save_file")):
        os.makedirs(os.path.join(options.dst_path, "save_file"))
        os.makedirs(os.path.join(options.dst_path, "cert_file"))
    log_file = os.path.join(options.dst_path, "logs")
    loggingFormat = "%(levelname)s-%(name)s-%(asctime)s-<%(message)s>"
    formatter = logging.Formatter(loggingFormat)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    logger = logging.getLogger("")
    logger.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.info("start process pcap")
    logging.info(options.corporation)
    os.system(
        "python dpkt_main.py -sf {} -dd {} -cp {}"
        .format(options.src_path, options.dst_path,options.corporation))