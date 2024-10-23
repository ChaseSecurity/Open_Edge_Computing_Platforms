import os
import argparse
import logging
import sys


def getfilename(dir_path, files=[]):
    if os.path.isdir(dir_path):
        name = os.listdir(dir_path)
        for i in name:
            getfilename(os.path.join(dir_path, i))
    if os.path.isfile(dir_path) and dir_path.endswith(".pcap"):
        files.append(dir_path)
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-src_dir", "--src_dir", type=str, default=None)
    parser.add_argument('-ip', '--ip', type=str, default=None)
    parser.add_argument('-cp','--corporation',type=str,default=None,help="tt or wxy")
    parser.add_argument('-sd', '--start_date', type=str, default=None)
    parser.add_argument('-ed', '--end_date', type=str, default=None)
    parser.add_argument("-dst_dir", "--dst_dir", type=str, default=None)
    options = parser.parse_args()

    log_file = os.path.join(options.dst_dir, "logs")
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
    src_dir = os.path.join(options.src_dir, options.ip, "tcpdump")
    dst_dir = os.path.join(options.dst_dir, options.ip)
    ip = options.ip
    start_date = options.start_date
    end_date = options.end_date
    dir_list = []
    corporation = options.corporation
    for date_name in os.listdir(src_dir):
        if date_name >= start_date and date_name <= end_date:
            dir_list.append(os.path.join(src_dir, date_name))
    logger.info("src_dir_list is {}".format(dir_list))

    filelist = []
    for item in dir_list:
        filelist += getfilename(item)
    filelist = list(set(filelist))
    logger.info("filelist len is {}".format(len(filelist)))
    filelist = list(set(filelist))
    # logger.info(filelist)
    filelist = sorted(filelist,
                      key=lambda x: int(
                          x.split("/")[-1].split(".")[0].split("_")[0] + x.
                          split("/")[-1].split(".")[0].split("_")[1]))
    logger.info("sorted")
    logger.info(filelist)
    for file in filelist:
        date_name = file.split("/")[-4]
        dir_end_name = file.split("/")[-1][:-5]
        new_dst_dir = os.path.join(dst_dir, date_name, dir_end_name)
        if not os.path.isdir(os.path.join(new_dst_dir, "save_file")):
            os.makedirs(os.path.join(new_dst_dir, "save_file"))
            os.makedirs(os.path.join(new_dst_dir, "cert_file"))
        logger.info("{} has been create".format(new_dst_dir))
        os.system(
            "python dpkt_main.py -sf {} -dd {} -cp {}"
            .format(file, new_dst_dir,corporation))