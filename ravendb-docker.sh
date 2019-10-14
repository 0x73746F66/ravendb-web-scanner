#!/usr/bin/env bash

# /mnt/share/RavenDB/config/license.json
mkdir -p /mnt/share/RavenDB/mnt/share/RavenDB/data /mnt/share/RavenDB/config /mnt/share/RavenDB/backup

# /mnt/share/RavenDB/config/settings.json
# {
#     "ServerUrl": "http://127.0.0.1:8080",
#     "PublicServerUrl": "http://ravendb.langton.cloud:8080",
#     "Setup.Mode": "None",
#     "Server.LocalRootPath": "/opt/RavenDB/Backup",
#     "Security.Certificate.Path": "/opt/RavenDB/",
#     "Security.Certificate.Password": ""
# }

docker pull ravendb/ravendb:4.2-ubuntu-latest && \
docker run -d --name ravendb \
    --nprocs 9 \
    -m $(grep MemTotal /proc/meminfo | awk '{print $2}')m \
    --memory-reservation $(expr $(grep MemTotal /proc/meminfo | awk '{print $2}') / 4)m \
    --oom-kill-disable \
    -p "8080:8080" \
    -p "38888:38888" \
    -e RAVEN_ServerUrl_Tcp=38888 \
    -e RAVEN_Setup_Mode='None' \
    -e RAVEN_Security_UnsecuredAccessAllowed='PrivateNetwork' \
    --restart=unless-stopped \
    --mount type=bind,src=/mnt/share/RavenDB/data,dst=/opt/RavenDB/Server/RavenData \
    --mount type=bind,src=/mnt/share/RavenDB/config/settings.json,dst=/opt/RavenDB/settings.json,readonly \
    --mount type=bind,src=/mnt/share/RavenDB/backup,dst=/opt/RavenDB/Backup \
    ravendb/ravendb:4.2-ubuntu-latest
