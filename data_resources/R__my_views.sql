-- CREATE USER pi
-- WITH PASSWORD NULL;

CREATE DATABASE west_end_646
WITH OWNER postgres
ENCODING 'UTF8';

\c west_end_646;

CREATE SCHEMA occupancy_schema
  AUTHORIZATION postgres
  CREATE TABLE occupancy
  (
    datetime  TIMESTAMPTZ NOT NULL PRIMARY KEY,
    occupancy INT
  )
  CREATE TABLE all_info
  (
    datetime TIMESTAMPTZ NOT NULL PRIMARY KEY,
    mac      CHAR(17)
  );


