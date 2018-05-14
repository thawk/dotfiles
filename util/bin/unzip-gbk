#!/usr/bin/env python
# -*- coding: utf-8 -*-
# unzip-gbk.py

import os
import sys
import zipfile
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--encoding", help="encoding for filename, default gbk")
parser.add_argument("-l", help="list filenames in zipfile, do not unzip", action="store_true")
parser.add_argument("file", help="process file.zip")
args = parser.parse_args()
print("Processing File " + args.file)

file=zipfile.ZipFile(args.file,"r");
if args.encoding:
    print("Encoding " + args.encoding)
for name in file.namelist():
    if args.encoding:
        utf8name=name.decode(args.encoding)
    else:
        utf8name=name.decode('gbk')
    pathname = os.path.dirname(utf8name)
    if args.l:
        print("Filename " + utf8name)
    else:
        print("Extracting " + utf8name)
        if not os.path.exists(pathname) and pathname!= "":
            os.makedirs(pathname)
        data = file.read(name)
        if not os.path.exists(utf8name):
            fo = open(utf8name, "w")
            fo.write(data)
            fo.close
file.close()
