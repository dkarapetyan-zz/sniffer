CREATE USER pi
WITH PASSWORD NULL;

CREATE DATABASE west_end_646
WITH OWNER = "pi"
ENCODING = 'UTF8';

-- GRANT ALL PRIVILEGES ON DATABASE west_end_646 TO pi;

\connect west_end_646;

CREATE SCHEMA occupancy_schema
  AUTHORIZATION "pi"
  CREATE TABLE occupancy
  (
    date      DATE NOT NULL,
    occupancy INT
  )
  CREATE TABLE all_info
  (
    date DATE NOT NULL,
    mac  CHAR(17),
    ssid VARCHAR(64)
  );


