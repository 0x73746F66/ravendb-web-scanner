#!/usr/bin/env bash

SCHEMA=public
DB=certwatch
HOST=crt.sh
PORT=5432
USER='guest --no-password'
DIR=$(pwd)

mkdir -p $DIR

psql -h $HOST -p $PORT -U $USER -Atc "select tablename from pg_tables where schemaname='$SCHEMA'" $DB |\
  while read TBL; do
    echo "Checking $TBL"
    if [ ! -f "$DIR/$TBL.csv" ]; then
      psql \
          -h $HOST \
          -p $PORT \
          -U $USER \
          -c "COPY $SCHEMA.$TBL TO STDOUT DELIMITER ',' CSV HEADER" $DB \
            > $DIR/$TBL.csv.part && \
              mv $DIR/$TBL.csv.part $DIR/$TBL.csv
    else
      echo "$TBL.csv Exists"
    fi
  done
