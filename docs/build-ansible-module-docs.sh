#!/bin/bash

CWD=`pwd`
MODULES_OUTPUT="$CWD/integrations/ansible/modules/source"



git clone https://github.com/napalm-automation/napalm-ansible.git napalm_ansible_repo
cd napalm_ansible_repo

# Change to master after next napalm-ansible release
git checkout develop

pip install -r requirements-dev.txt
pip install .
py.test -c /dev/null
cp module_docs/* $MODULES_OUTPUT/

cd $CWD

