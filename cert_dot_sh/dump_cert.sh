#!/usr/bin/env bash

SCHEMA=public
DB=certwatch
HOST=crt.sh
PORT=5432
USER=guest
DIR=$(pwd)

mkdir -p $DIR

psql -h $HOST -p $PORT -U $USER -Atc "select tablename from pg_tables where schemaname='$SCHEMA'" $DB |\
  while read TBL; do
    psql -h $HOST -p $PORT -U $USER -c "COPY $SCHEMA.$TBL TO STDOUT DELIMITER ',' CSV HEADER" $DB > $DIR/$TBL.csv
  done