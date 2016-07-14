CREATE ROLE pi
NOSUPERUSER INHERIT CREATEROLE;

CREATE ROLE pi LOGIN
PASSWORD '';


CREATE DATABASE pi
WITH OWNER = "pi"
ENCODING = 'UTF8'
TABLESPACE = pg_default
LC_COLLATE = 'English_United States.1252'
LC_CTYPE = 'English_United States.1252'
CONNECTION LIMIT = -1;

CREATE SCHEMA occupancy_schema
  AUTHORIZATION "pi";


CREATE TABLE occupancy
(
  date      DATE NOT NULL,
  occupancy INT
);

CREATE TABLE all_info
(
  date DATE NOT NULL,
  mac  CHAR(17),
  ssid VARCHAR(64)
);


