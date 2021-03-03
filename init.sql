CREATE TABLE auth_users(
id serial,
username varchar(40) NOT NULL,
email varchar(40) NOT NULL,
password text,
salt varchar(40)
 );