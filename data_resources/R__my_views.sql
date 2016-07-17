CREATE SCHEMA west_end_646
  CREATE TABLE occupancy
  (
    datetime  TIMESTAMPTZ NOT NULL PRIMARY KEY,
    occupancy INT
  )
  CREATE TABLE sniffed
  (
    datetime TIMESTAMPTZ NOT NULL PRIMARY KEY,
    mac      CHAR(17)
  );


