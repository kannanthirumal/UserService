/*
database creation
*/

CREATE DATABASE UserServiceDb;
USE UserServiceDb;
CREATE USER UserServiceDbUser;
GRANT ALL PRIVILEGES ON UserServiceDb.* TO UserServiceDbUser;

/*
    security/SecurityConfig
*/

- User and Client info in (security/SecurityConfig) are just being stored in-memory
- I did a google search -> "Implement core services with JPA"
- this link -> https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html
- to make it persist
- I will be creating models(entitites)/repositories/services using the above documentation
- I will be creating these within "security" package - as it is related to securityconfig

/*
    SecurityConfigPersist
*/

- duplicate the SecurityConfig - name it SecurityConfigPersist
- commented out the parts of the code that I don't want (in-memory related)

/*
    - Add "@Lob" to "Authorization" table columns
    - wherever the column length exceeds a certain limit of memory
    - to make sure table gets created without any error
    - otherwise no table gets created
*/