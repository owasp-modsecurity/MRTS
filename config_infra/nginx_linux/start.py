#!/usr/bin/env python3

import os
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
server_root_dir = os.path.join(current_dir, 'infra')

original_cwd = os.getcwd()

try:
    # Change to the server root directory before launching nginx
    # Necessary because modsecurity_rules_file does not use the prefix but uses pwd
    os.chdir(server_root_dir)

    startcommand = [
        'nginx',
        '-p', server_root_dir,
        '-c', 'nginx.conf',
        '-g', 'error_log log/error.log info;' # avoid permission error with compiled log path
    ]

    subprocess.run(startcommand, check=True)

finally:
    os.chdir(original_cwd)