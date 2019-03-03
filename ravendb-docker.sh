#!/usr/bin/env bash

# /mnt/ravendb/config/license.json
mkdir -p /mnt/ravendb/mnt/ravendb/data /mnt/ravendb/config /mnt/ravendb/backup

# /mnt/ravendb/config/settings.json
# {
#     "ServerUrl": "http://127.0.0.1:8080",
#     "PublicServerUrl": "http://ravendb.langton.cloud:8080",
#     "Setup.Mode": "None",
#     "Server.LocalRootPath": "/opt/RavenDB/Backup",
#     "Security.Certificate.Path": "/opt/RavenDB/",
#     "Security.Certificate.Password": ""
# }

docker run -d --name ravendb \
    -p "8080:8080" \
    -p "38888:38888" \
    -e RAVEN_ServerUrl_Tcp=38888 \
    -e RAVEN_Setup_Mode='None' \
    -e RAVEN_Security_UnsecuredAccessAllowed='PrivateNetwork' \
    --restart=unless-stopped \
    --mount type=bind,src=/mnt/ravendb/data,dst=/opt/RavenDB/Server/RavenData \
    --mount type=bind,src=/mnt/ravendb/config/settings.json,dst=/opt/RavenDB/settings.json,readonly \
    --mount type=bind,src=/mnt/ravendb/backup,dst=/opt/RavenDB/Backup \
    ravendb/ravendb:4.1.4-ubuntu.18.04-x64
