#!/usr/bin/env python3

import os
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
server_root_dir = os.path.join(current_dir, 'infra')
nginx_conf_path = os.path.join(server_root_dir, 'nginx.conf')

original_cwd = os.getcwd()

try:
    # Change to the server root directory before launching nginx
    # Necessary because modsecurity_rules_file does not use the prefix but uses pwd
    os.chdir(server_root_dir)

    stopcommand = [
        'nginx',
        '-p', server_root_dir,
        '-c', nginx_conf_path,
        '-s', 'stop'
    ]

    subprocess.run(stopcommand, check=True)

finally:
    os.chdir(original_cwd)