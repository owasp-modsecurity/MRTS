#!/usr/bin/env python3

import sys
import os
import glob
import msc_pyparser
import argparse
import re

VARSLIST = []
USEDVARSLIST = []

OPERATORSLIST = []
USEDOPERATORSLIST = []

def readtokens():
    global VARSLIST
    global OPERATORSLIST
    dname = os.path.dirname(__file__)
    try:
        with open(os.path.join(dname, "VARS.txt"), "r") as f:
            VARSLIST = [l.strip() for l in f.readlines() if l.strip() != ""]
    except Exception as e:
        print("Can't open VARS.txt")
        print(", ".join(e.args))
        return False
    return True


def fillused(struct):
    global USEDVARSLIST
    for s in struct:
        if s['type'].lower() == "secrule":
            for v in s['variables']:
                if USEDVARSLIST.count(v['variable']) == 0:
                    USEDVARSLIST.append(v['variable'])

def errmsgf(msg):
    if 'message' in msg and msg['message'].strip() != "":
        print("%sfile={file}, line={line}, endLine={endLine}, title={title}: {message}".format(**msg) % (msg['indent']*" "))
    else:
        print("%sfile={file}, line={line}, endLine={endLine}, title={title}".format(**msg) % (msg['indent']*" "))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MRTS collect tool")
    parser.add_argument("-r", "--rules", metavar='/path/to/mrts/*.conf', type=str,
                            nargs='*', help='Directory path to MRTS rules', required=True,
                            action="append")
    args = parser.parse_args()

    mrtspath = []
    for l in args.rules:
        mrtspath += l

    retval = 0
    try:
        flist = mrtspath
        flist.sort()
    except Exception as e:
        print("Can't open files in given path!")
        print(", ".join(e.args))
        sys.exit(1)

    if len(flist) == 0:
        print("List of files is empty!")
        sys.exit(1)

    rc = readtokens()
    if rc != True:
        sys.exit(1)

    parsed_structs = {}

    for f in flist:
        try:
            with open(f, 'r') as inputfile:
                data = inputfile.read()
        except:
            print("Can't open file: %s" % f)
            sys.exit(1)

        ### check file syntax
        print("Config file: %s" % (f))
        try:
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(data)
            print(" Parsing ok.")
            parsed_structs[f] = mparser.configlines
            fillused(parsed_structs[f])
        except Exception as e:
            err = e.args[1]
            if err['cause'] == "lexer":
                cause = "Lexer"
            else:
                cause = "Parser"
            print("Can't parse config file: %s" % (f))
            errmsgf({
                'indent' : 2,
                'file'   : f,
                'title'  : "%s error" % (cause),
                'line'   : err['line'],
                'endLine': err['line'],
                'message': "can't parse file"})
            retval = 1
            continue

    print("\n=====")
    print("Covered TARGETs: %s\n" % (", ".join(USEDVARSLIST)))
    unusedvars = [v for v in VARSLIST if v not in USEDVARSLIST]
    print("UNCOVERED TARGETs:", ", ".join(unusedvars))


    sys.exit(retval)

