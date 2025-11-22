#!/usr/bin/env python3
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
import sys
import subprocess
import regress
import re


def get_ipaddr(count):
    octet1 = count % 254
    octet2 = count // 254

    return "10.0.%d.%d" % (octet2 + 1, octet1 + 1)


def nmap(count):
    ipaddr = get_ipaddr(count)

    log = open("/tmp/nmap.log", "a")
    result = subprocess.run(
        ["nmap", "-S", "127.0.0.1", "-e", "lo0", "-sS", "-O", "-p1,23", ipaddr],
        capture_output=True,
        text=True,
        check=False,
    )

    oses = ""

    output = ""
    for line in result.stdout.splitlines():
        #        if re.match("^(SInfo|TSeq|T[0-9]|PU)", line):
        output += line
        res = re.match("OS (guesses|details): (.*)", line)
        if res:
            oses = res.group(2)
        elif re.match("^No exact OS", line):
            oses = None

    res = 0
    if oses:
        if oses == prints[count]:
            print("+", end=" ")
            res = 1
        elif oses.find(prints[count]) != -1:
            print("-", end=" ")
            res = 2
        else:
            print("?", end=" ")
            print(
                "Wanted: '%s' but got '%s':\n%s" % (prints[count], oses, output),
                file=log,
            )
            failures.append("%d:" % count + prints[count] + oses + ":\n" + output)
    else:
        print("Wanted: '%s' but got nothing:\n%s" % (prints[count], output), file=log)
        failures.append("%d:" % count + prints[count] + "No match:\n" + output)
        print("_", end=" ")

    sys.stdout.flush()
    log.close()
    return res


def make_configuration(filename, fingerprints):
    output = open(filename, "w")
    input = open(fingerprints, "r")

    print(
        """create template
set template default tcp action closed
add template tcp port 23 open
""",
        file=output,
    )
    count = 0
    r = re.compile(r"\s*$")
    m = re.compile(r"^Fingerprint ([^#]*)$")
    for line in input:
        line = r.sub("", line)
        res = m.match(line)
        if not res:
            continue

        fname = res.group(1)

        prints[count] = fname
        ipaddr = get_ipaddr(count)

        # Create template
        print("bind %s template" % ipaddr, file=output)
        print('set %s personality "%s"' % (ipaddr, fname), file=output)

        count += 1

    output.close()
    input.close()

    return count


# Main

failures = []
prints = {}

number = make_configuration("config.nmap", "../nmap.prints")

reg = regress.regress("Nmap fingerprints", "../honeyd", "config.nmap")
reg.start_honeyd(reg.configuration)

reg.fe.read()

success = 0
partial = 0
nothing = 0
for count in range(0, number):
    res = nmap(count)
    if res == 1:
        success += 1
    elif res == 2:
        partial += 1
    else:
        nothing += 1
    reg.fe.read()

reg.stop_honeyd()

print(
    "\nSuccesses: %d, Partials: %d, Nothing: %d of %d"
    % (success, partial, nothing, number)
)
for line in failures:
    print(line)
