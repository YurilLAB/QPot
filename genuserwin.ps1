# Run genuser.sh within qpotinit, prepare path and file
# Define the volume paths
$homePath = $Env:USERPROFILE + "\qpotce"
$nginxpasswdPath = $homePath + "\data\nginx\conf\nginxpasswd"

# Ensure nginxpasswd file exists
if (-Not (Test-Path $nginxpasswdPath)) {
    New-Item -ItemType File -Force -Path $nginxpasswdPath
}

# Run the Docker container without specifying UID / GID
docker run -v "${homePath}:/data" --entrypoint bash -it dtagdevsec/qpotinit:24.04.1 "/opt/qpot/bin/genuser.sh"
