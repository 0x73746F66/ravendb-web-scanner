#!/usr/bin/env bash

mkdir -p /mnt/ravendb/mnt/ravendb/data /mnt/ravendb/config /mnt/ravendb/backup

# /mnt/ravendb/config/settings.json
# {
#     "ServerUrl": "http://127.0.0.1:8080",
#     "Setup.Mode": "Initial",
#     "Server.LocalRootPath": "/opt/RavenDB/Backup"
# }

# /mnt/ravendb/config/license.json


docker run -d --rm --name ravendb \
    -p 8080:8080 \
    -p 38888:38888 \
    -e RAVEN_ARGS='--Setup.Mode=None' \
    -e RAVEN_Security_UnsecuredAccessAllowed='PrivateNetwork' \
    --mount type=bind,src=/mnt/ravendb/data,dst=/opt/RavenDB/Server/RavenData \
    --mount type=bind,src=/mnt/ravendb/config,dst=/opt/RavenDB/config \
    --mount type=bind,src=/mnt/ravendb/backup,dst=/opt/RavenDB/Backup \
    ravendb/ravendb:4.1.4-ubuntu.18.04-x64