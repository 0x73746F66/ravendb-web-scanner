#!/usr/bin/env bash
WORKDIR=/home/chris/workspace/gitlab/open-net-scans
CHDIR=src
SCRIPT=process_ftp.py
LOGFILE=${WORKDIR}/${CHDIR}/process_ftp.log
cd ${WORKDIR}
running=$(pgrep -f ${SCRIPT})
touch ${LOGFILE}
if [ -z "${running}" ]; then
    echo '[CRON] Vitrualenv' >> ${LOGFILE}
    source .env/bin/activate
    cd ${CHDIR}
    echo '[CRON] Running' >> ${LOGFILE}
    ionice -c2 -n7 python ${SCRIPT} -vvvv -l ${LOGFILE} --cron True &
    deactivate
else
    echo '[CRON] detected script is still active' >> ${LOGFILE}
    echo "PID:\n${running}" >> ${LOGFILE}
fi
exit 0