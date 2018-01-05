#!/usr/bin/env python3

# RouterOS binary extractor by BigNerd95

import requests, sys, io, PySquashfsImage

MTDL_URL = "https://download2.mikrotik.com/routeros/"
SQFS_OFFSET = 0x1000

def download_ROS(version, arch):
    url = MTDL_URL + version + "/routeros-" + arch + "-" + version + ".npk"
    fw = requests.get(url, stream=True)
    if fw.status_code == requests.codes.ok and len(fw.content) > 0:
        return fw.content
    else:
        raise Exception("Error downloading firmware!")

def get_binary(fw, path):
    fwfd = io.BytesIO(fw)
    sqfs = PySquashfsImage.SquashFsImage(offset=SQFS_OFFSET)
    sqfs.setFile(fwfd)

    for f in sqfs.root.findAll():
        if f.getPath() == path:
            return f.getContent()

    raise Exception("Path not found!")

def main(version, arch, binary_path, save_name):
    print("Downloading firmware...")
    try:
        fw = download_ROS(version, arch)
    except Exception as e:
        print(e)
        return

    print("Extracting", binary_path)
    try:
        binary = get_binary(fw, binary_path)
    except Exception as e:
        print(e)
        return

    with open(save_name, "wb") as f:
        f.write(binary)

    print(binary_path, "saved as", save_name)

if __name__ == "__main__":
    if len(sys.argv) == 5:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print("Usage:", sys.argv[0], "VERSION ARCH BIN_PATH_TO_EXTRACT SAVE_NAME")
        print("Example:", sys.argv[0], "6.38.4 x86 /nova/bin/www www_6384_x86")
