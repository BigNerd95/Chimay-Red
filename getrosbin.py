#!/usr/bin/env python2
"""RouterOS binary extractor by BigNerd95"""
import io
import sys

import PySquashfsImage
import requests


DOWNLOAD_BASE_URL = "https://download2.mikrotik.com/routeros/"
SQUASH_FS_OFFSET = 0x1000


def fetch_ros_npk(version, arch):  # -> str
    url = DOWNLOAD_BASE_URL + version + "/routeros-" + arch + "-" + version + ".npk"
    print(url)
    response = requests.get(url, stream=True)
    if (
        response.status_code == 200
        and response.headers.get('Content-Type') == 'application/octet-stream'
        and len(response.content) > 0
    ):
        return response.content
    else:
        raise Exception("Error downloading firmware!")


def get_binary(squash_str, path):  # -> str
    f = io.BytesIO(squash_str)
    squash_fs = PySquashfsImage.SquashFsImage(offset=SQUASH_FS_OFFSET)
    squash_fs.setFile(f)

    try:
        squashed_file = filter(
            lambda x: x.getPath() == path,
            squash_fs.root.findAll()
        )[0]
    except IndexError:
        raise Exception("File not found: %s" % path)

    return squashed_file.getContent()


def main(version, arch, binary_path, save_name=''):
    print("Downloading firmware...")
    try:
        npk_str = fetch_ros_npk(version, arch)
    except Exception as e:
        print(e)
        return

    print("Extracting", binary_path)
    try:
        binary = get_binary(npk_str, binary_path)
    except Exception as e:
        print(e)
        return

    binary_filename = binary_path.split('/')[-1]
    save_name = save_name if save_name else 'bin/%s_%s_%s' \
        % (binary_filename, arch, version)

    with open(save_name, "wb") as f:
        f.write(binary)

    print("%s saved as %s" % (binary_path, save_name))


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        version, arch, binary_path = sys.argv[1], sys.argv[2], sys.argv[3]
        if len(sys.argv) == 5:
            filename_to_save = sys.argv[4]
        else:
            filename_to_save = ''
        main(version, arch, binary_path, filename_to_save)
    else:
        print("Usage: \n\tpython %s VERSION ARCH BIN_PATH_TO_EXTRACT SAVE_NAME\n" % sys.argv[0])
        print("Example:\n\tpython %s 6.38.4 x86 /nova/bin/www www_6384_x86" % sys.argv[0])
