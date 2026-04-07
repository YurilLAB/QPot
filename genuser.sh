#!/usr/bin/env bash
QPOT_REPO=$(grep -E "^QPOT_REPO" .env | cut -d "=" -f2-)
QPOT_VERSION=$(grep -E "^QPOT_VERSION" .env | cut -d "=" -f2-)
USER=$(id -u)
USERNAME=$(id -un)
GROUP=$(id -g)
echo "### Repository:        ${QPOT_REPO}"
echo "### Version Tag:       ${QPOT_VERSION}"
echo "### Your User Name:    ${USERNAME}"
echo "### Your User ID:      ${USER}"
echo "### Your Group ID:     ${GROUP}"
echo
docker run -v $HOME/qpotce:/data --entrypoint "bash" -it -u "${USER}":"${GROUP}" "${QPOT_REPO}"/qpotinit:"${QPOT_VERSION}" "/opt/qpot/bin/genuser.sh"
