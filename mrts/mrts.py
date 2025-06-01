#!/usr/bin/env python3

import argparse
import glob
import runpy
import shutil
import subprocess
import sys
import os


def clean_generated_directories(genrules, gentests, verbose):
    old_rules = glob.glob(os.path.join(genrules, "*.conf"))
    old_test = glob.glob(os.path.join(gentests, "*.yaml"))
    for rule in old_rules:
        os.remove(rule)
    for test in old_test:
        os.remove(test)
    if verbose:
        print("Cleaned generated directories")


def generate_rules(testconfig, genrules, gentests, verbose):
    testconfig = os.path.join(testconfig, "*.yaml")

    current_dir = os.path.dirname(os.path.abspath(__file__))
    generate_rules_script = os.path.join(current_dir, "generate-rules.py")

    genrule_stdout = sys.stdout if verbose else subprocess.DEVNULL
    subprocess.run([generate_rules_script, "-r", *glob.glob(testconfig), "-e",genrules, "-t", gentests],
                   stdout=genrule_stdout)


def launch_albedo():
    if not shutil.which("albedo"):
        print("Failure: albedo not installed or found in system PATH")
        sys.exit(1)

    return subprocess.Popen(
        ["albedo", "-b", "127.0.0.1", "-p", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)


def execute_test_set(ftwconfig, infra, gentests, verbose, fail_fast):
    if not shutil.which("go-ftw"):
        print("Failure: go-ftw not installed or found in system PATH")
        sys.exit(1)

    if ftwconfig is None:
        ftwconfig = os.path.join(infra, "ftw.mrts.config.yaml")

    if fail_fast:
        go_ftw = subprocess.Popen(
            ["go-ftw", "run", "--config", ftwconfig, "--dir", gentests, "--wait-for-expect-status-code", "200", "--fail-fast"],
            stdout=subprocess.PIPE
        )
    else:
        go_ftw = subprocess.Popen(
            ["go-ftw", "run", "--config", ftwconfig, "--dir", gentests, "--wait-for-expect-status-code", "200"],
            stdout=subprocess.PIPE
        )

    stdout = ""
    for line in go_ftw.stdout:
        stdout += line.decode("utf-8")
        if verbose:
            print(line.decode("utf-8"), end="")

    if '💥' in stdout:
        print("💥💥💥 Failure: test set failed")
    elif '🎉' in stdout:
        print("🎉🎉🎉 Success: test set passed")
    else:
        print("Failure: Incorrect go-ftw output")


def write_mrts_load(infra_path, genrules_path, verbose):
    load_file_path = os.path.join(infra_path, "mrts.load")
    with open(load_file_path, "w") as f:
        f.write(f"Include {genrules_path}\n")

    if verbose:
        print(f"File '{load_file_path}' created successfully with content: Include {genrules_path}")


def delete_mrts_load(infra_path, verbose):
    file_path = os.path.join(infra_path, "mrts.load")
    if os.path.exists(file_path):
        os.remove(file_path)
        if verbose:
            print(f"File '{file_path}' has been deleted.")
    else:
        if verbose:
            print(f"File '{file_path}' does not exist.")


def main(infra, ftwconfig, testconfig, genrules, gentests, verbose, clean, fail_fast):

    if not os.getcwd() == os.path.dirname(os.path.dirname(os.path.abspath(__file__))):
        print("This script can only run from the MRTS root directory")
        sys.exit(1)

    # Optionally, remove previous .conf and .yaml generated
    if clean:
        clean_generated_directories(genrules, gentests, verbose)

    # Step 1: generate rules and tests
    print("Generate rules and tests")
    generate_rules(testconfig, genrules, gentests, verbose)

    # Step 2: start backend
    print("Launch backend")
    backend = launch_albedo()

    # Step 3: create temporary file in infra to include rules, figuring out the absolute path dynamically
    infra_path = os.path.join(infra, "infra")
    genrules_abs_path = os.path.join(os.path.abspath(genrules), "*.conf")
    write_mrts_load(infra_path, genrules_abs_path, verbose)

    # Step 4: launch infrastructure from start script
    print("Launch infrastructure")
    runpy.run_path(os.path.join(infra, "start.py"))

    # Step 5: use go-ftw to run tests
    print("Executing test set...")
    execute_test_set(ftwconfig, infra, gentests, verbose, fail_fast)

    # Step 6: shutdown backend
    backend.terminate()
    print("Backend shutdown")

    # Step 7: shutdown infrastructure from stop script
    runpy.run_path(os.path.join(infra, "stop.py"))
    print("Infrastructure shutdown")

    # Step 8: remove temporary file including rules
    delete_mrts_load(infra_path, verbose)

    # The end
    print("MRTS completed")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="MRTS global utility")
    parser.add_argument("-i", "--infrastructure", metavar='/path/to/infra/', type=str,
                            help='Directory path to infrastructure to be tested', required=True)
    parser.add_argument("-r", "--rulesdef", metavar='/path/to/mrts/*.yaml', type=str,
                            help='Directory path to MRTS rules definition', required=True)
    parser.add_argument("-e", "--expdir", metavar='/path/to/mrts/rules/', type=str,
                            help='Directory path to generated MRTS rules', required=True)
    parser.add_argument("-t", "--testdir", metavar='/path/to/mrts/tests/', type=str,
                            help='Directory path to generated MRTS tests', required=True)
    parser.add_argument("-c", "--clean", action='store_true',
                            help='Clean generated rules and tests directories before new rule generation',
                            required=False, default=False)
    parser.add_argument("-f", "--ftwconfig", metavar='/path/to/mrts/ftw.mrts.config.yaml', type=str,
                            help='go-ftw config file', required=False, default=None)
    parser.add_argument("-v", "--verbose", action='store_true',
                            help='Verbose output', required=False, default=False)
    parser.add_argument("-F", "--fail_fast", action='store_true',
                            help='Fail on first failed test', required=False, default=False)

    args = parser.parse_args()

    main(args.infrastructure, args.ftwconfig, args.rulesdef, args.expdir, args.testdir, args.verbose, args.clean, args.fail_fast)

