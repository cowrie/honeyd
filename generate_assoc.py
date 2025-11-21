#!/usr/bin/env python3

import os
import sys
import re

def get_xprobe(filename):
    file = open(filename, "r")

    m = re.compile(r"\s*$")
    m2 = re.compile("#.*")
    for line in file:
        line = m2.sub("", line)
        line = m.sub("", line)
        if not len(line):
            continue

        res = re.search(r'OS_ID\s*=\s*"(.*)"', line)
        if not res:
            continue

        xprobe.append(res.group(1))

    file.close()

def find_match(fingerprint):
    tokens = fingerprint.split(" ")
    bestname = None
    maxcount = 0

    for name in xprobe:
        count = 0
        for token in tokens:
            if len(token) <= 1 and not re.match("[0-9]", token):
                continue
            if token == "Release" or token == "Kernel" or token == "Server":
                continue
            if name.find(token) != -1:
                if len(token) >= 5:
                    count += 1
                count += 1

        if count > maxcount:
            maxcount = count
            bestname = name

    if maxcount > 1 and bestname:
        print("%s;%s" % (fingerprint, bestname))
    else:
        print("#%s;" % fingerprint)

def make_configuration(filename):
    file = open(filename, "r")

    r = re.compile(r'\s*$')
    m = re.compile("^Fingerprint ([^#]*)$")
    for line in file:
        line = r.sub("", line)
        res = m.match(line)
        if not res:
            continue

        fname = res.group(1)

        find_match(fname)

    file.close()

# Main

xprobe = []
get_xprobe("xprobe2.conf")
make_configuration("nmap-os-db")
