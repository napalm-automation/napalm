#!/bin/bash
set -e

CWD=`pwd`
MODULES_OUTPUT="$CWD/integrations/ansible/modules/source"

# Cleanup old repo
if [ -d "napalm_ansible_repo" ]; then
    rm -rf napalm_ansible_repo
fi

# Pinned release (tag + commit SHA, since tags can be moved)
NAPALM_ANSIBLE_TAG="1.1.0"
NAPALM_ANSIBLE_SHA="150ddb3a87e37c36a7077bc8b39521bdbd8c8e1b"

git clone --depth 1 --branch "$NAPALM_ANSIBLE_TAG" https://github.com/napalm-automation/napalm-ansible.git napalm_ansible_repo
cd napalm_ansible_repo

if [ "$(git rev-parse HEAD)" != "$NAPALM_ANSIBLE_SHA" ]; then
    echo "napalm-ansible $NAPALM_ANSIBLE_TAG does not match pinned SHA $NAPALM_ANSIBLE_SHA" >&2
    exit 1
fi

uv pip install .
# Needed until this is fixed: 
#   https://github.com/napalm-automation/napalm-ansible/issues/216
uv pip install setuptools packaging
uv run pytest -c /dev/null
cp module_docs/* $MODULES_OUTPUT/

cd $CWD

