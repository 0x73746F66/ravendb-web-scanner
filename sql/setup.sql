-- docker run --name=mysql -d -p3306:3306 mysql/mysql-server:5.7
-- docker logs mysql 2>&1 | grep GENERATED
-- docker exec -it mysql mysql -uroot -p

UPDATE mysql.user SET host='%' WHERE User='root';
FLUSH PRIVILEGES;

CREATE SCHEMA IF NOT EXISTS `scans` DEFAULT CHARACTER SET utf8 ;

delimiter |

CREATE TRIGGER `scans`.`scan_log_triggerscan_log_trigger` AFTER INSERT ON scan_log
  FOR EACH ROW
  BEGIN
	DECLARE tldid INT ;
	DECLARE domainid INT ;
	DECLARE nsid INT ;

    INSERT INTO `scans`.`nameservers` SET `nameserver`=NEW.nameserver, `ttl`=NEW.ttl
    ON DUPLICATE KEY
    UPDATE `id`=LAST_INSERT_ID(id), `nameserver`=VALUES(`nameserver`), `ttl`=VALUES(`ttl`) ;
	SET nsid = LAST_INSERT_ID() ;
	IF nsid IS NULL OR nsid = '' THEN
		SELECT `id` INTO nsid FROM `scans`.`nameservers` WHERE `name`=NEW.nameserver LIMIT 1;
		END IF;

    INSERT INTO `scans`.`tld` SET `name`=NEW.tld, `local_file`=NEW.local_file, `czdap_id`=NEW.czdap_id, `last_scan`=NEW.scanned
    ON DUPLICATE KEY 
    UPDATE `id`=LAST_INSERT_ID(id), `name`=VALUES(`name`), `local_file`=VALUES(`local_file`), `czdap_id`=VALUES(`czdap_id`), `last_scan`=VALUES(`last_scan`) ;
    SET tldid = LAST_INSERT_ID() ;
	IF tldid IS NULL OR tldid = '' THEN
		SELECT `id` INTO tldid FROM `scans`.`tld` WHERE `name`=NEW.tld  LIMIT 1;
		END IF;

	INSERT INTO `scans`.`domain` SET `name`=NEW.domain, `tld_id`=tldid
	ON DUPLICATE KEY 
	UPDATE `id`=LAST_INSERT_ID(id), `name`=VALUES(`name`), `tld_id`=VALUES(`tld_id`) ;
	SET domainid = LAST_INSERT_ID() ;

	IF domainid IS NOT NULL AND domainid != '' THEN
		INSERT IGNORE INTO `scans`.`link_domain_ns` SET `domain_id`=domainid, `ns_id`=nsid ;
		END IF;

  END;
|

delimiter ;