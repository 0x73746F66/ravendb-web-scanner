-- docker run --name=mysql -d -p3306:3306 mysql/mysql-server:5.7
-- docker logs mysql 2>&1 | grep GENERATED
-- docker exec -it mysql mysql -uroot -p

UPDATE mysql.user SET host='%' WHERE User='root';
FLUSH PRIVILEGES;

CREATE SCHEMA IF NOT EXISTS `scans` DEFAULT CHARACTER SET utf8 ;