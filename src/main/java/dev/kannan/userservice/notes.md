/*
database creation
*/

CREATE DATABASE UserServiceDb;
USE UserServiceDb;
CREATE USER UserServiceDbUser;
GRANT ALL PRIVILEGES ON UserServiceDb.* TO UserServiceDbUser;