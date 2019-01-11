-- docker run --name=mysql -d -p3306:3306 mysql/mysql-server:5.7
-- docker logs mysql 2>&1 | grep GENERATED
-- docker exec -it mysql mysql -uroot -p

UPDATE mysql.user SET host='%' WHERE User='root';
FLUSH PRIVILEGES;

-- general
CREATE SCHEMA IF NOT EXISTS `scans` DEFAULT CHARACTER SET utf8 ;

CREATE TABLE `domain` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tld_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tld_UNIQUE` (`name`),
  UNIQUE KEY `tld_id_UNIQUE` (`tld_id`),
  CONSTRAINT `fk_domain_1` FOREIGN KEY (`tld_id`) 
    REFERENCES `tld` (`id`) 
    ON DELETE NO ACTION 
    ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `tld` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `local_file` varchar(255) DEFAULT NULL,
  `czdap_id` int(10) unsigned DEFAULT NULL,
  `last_scan` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tld_UNIQUE` (`name`),
  UNIQUE KEY `file_UNIQUE` (`local_file`),
  UNIQUE KEY `czdap_id_UNIQUE` (`czdap_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `nameservers` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `nameserver` varchar(255) NOT NULL,
  `ttl` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `nameserver_UNIQUE` (`nameserver`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `link_domain_ns` (
  `domain_id` int(10) unsigned NOT NULL,
  `ns_id` int(10) unsigned NOT NULL,
  KEY `pk` (`domain_id`,`ns_id`),
  KEY `fk_link_domain_ns_ns_idx` (`ns_id`),
  CONSTRAINT `fk_link_domain_ns_domain` FOREIGN KEY (`domain_id`) 
    REFERENCES `domain` (`id`) 
    ON DELETE NO ACTION 
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_link_domain_ns_ns` FOREIGN KEY (`ns_id`) 
    REFERENCES `nameservers` (`id`) 
    ON DELETE NO ACTION 
    ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
