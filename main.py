# Created by Meghadeep Roy Chowdhury 14/4/2021
# Modified by Davide Andreossi on 19/01/2022
# All rights reserved under GNU AGPLv3
# details: https://www.gnu.org/licenses/agpl-3.0.en.html

import os
import datetime
from pathlib import Path
import subprocess
import sys

# Kernel sign script path
sign_script_path = '/usr/src/kernels/{uname_release}/scripts/sign-file'
# Common kernel path
path_common = '/lib/modules/'
# main.py directory path
cert_path = os.path.join('/', 'home', 'dandreos', 'Documenti', 'Certificates_MOKUTILS')
# shell script to list kernel versions available
shell_scr = 'rpm -q kernel | sort -V'


class MOKKeyError(Exception):
    """ Machine Owner's Key not found in the keys directory """
    pass


class SignError(Exception):
    """ Error while signing the kernel modules """
    pass


def prepend(modules, common):
    # Using format()
    common += '{0}'
    modules = [common.format(i) for i in modules]
    return modules


def sign_and_log(run_script, module):
    global cert_path
    print('Signing ' + module)
    try:
        os.system(run_script)
        print('Signed ' + module)
        with open(cert_path + '/autosigner.log', 'a+') as f:
            f.write('Signed ' + module + '\n')
    except Exception as e:
        print('FAILURE: ' + module)
        print(e)
        with open(cert_path + '/autosigner.log', 'a+') as f:
            f.write(e + '\n')
            f.write(datetime.datetime.now().strftime('%c') + '\n')


def main():
    global sign_script_path

    # Get current kernel info
    kernel_current = os.uname().release

    # Get list of kernels
    kernels_present = subprocess.check_output(shell_scr, shell=True)
    kernels_present = kernels_present.decode().strip()
    # Get the most recently installed kernel
    if 'rpm' in shell_scr:
        kernel_updated = kernels_present.split('\n')[-1].split('kernel-')[-1]
    elif 'dpkg' in shell_scr:
        kernel_updated = kernels_present.split('\n')[-2].split('-image-')[-1].split('-generic')[0] + '-generic'
    # Check if user is forcing signature
    try:
        override = sys.argv[1]
    except:
        override = False
    # Only need to proceed if there's been a kernel update
    if kernel_current != kernel_updated or override == 'force':
        # if True:
        print('Updated kernel found: ' + kernel_updated)
        kernel_path = path_common + kernel_updated + '/'
        with open('modules.conf') as f:
            kernel_modules = f.readlines()
        # Remove whitespace characters like `\n` at the end of each line
        if kernel_modules[-1] == '\n':
            kernel_modules.pop()
        kernel_modules = [x.strip() for x in kernel_modules]
        modules_path = prepend(kernel_modules, kernel_path)
        # Check if keys exist
        print(cert_path)
        keys = [f.name for f in os.scandir(cert_path) if f.is_file()]
        if ('MOK.priv' in keys) and ('MOK.der' in keys):
            print('Keys found in keys directory.')
            public_key = os.path.join(cert_path, 'MOK.der')
            private_key = os.path.join(cert_path, 'MOK.priv')
            sign_script_path = sign_script_path.format(uname_release=kernel_updated)
            for i in modules_path:
                if i[-1] == '/':
                    mod_list = os.listdir(i[:-1])
                    for j in mod_list:
                        run_script = sign_script_path + ' sha256 ' + private_key + ' ' + public_key + ' ' + i + j
                        sign_and_log(run_script, i + j)
                else:
                    run_script = sign_script_path + ' sha256 ' + private_key + ' ' + public_key + ' ' + i
                    sign_and_log(run_script, i)
        else:
            print('Keys NOT FOUND')
            # with open(main_path + '/autosigner.log', 'a+') as f:
            #     f.write('Keys NOT FOUND. ' + datetime.datetime.now().strftime('%c') + '\n')
            raise MOKKeyError
    else:
        print('Kernel not updated, signing new kernels not required.')
        # with open(main_path + '/autosigner.log', 'a+') as f:
        #     f.write('Kernel not updated, signing new kernels not required. ' + datetime.datetime.now().strftime(
        #         '%c') + '\n')


if __name__ == '__main__':
    print('Service ran at ' + datetime.datetime.now().strftime('%c'))

    main()
