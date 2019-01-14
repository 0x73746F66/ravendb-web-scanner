DROP TRIGGER IF EXISTS `scans`.`scan_log_triggerscan_log_trigger` ;
SET FOREIGN_KEY_CHECKS = 0 ;
DROP TABLE IF EXISTS `scans`.`domain`
DROP TABLE IF EXISTS `scans`.`link_domain_ns`
DROP TABLE IF EXISTS `scans`.`nameservers`
DROP TABLE IF EXISTS `scans`.`scan_log`
DROP TABLE IF EXISTS `scans`.`tld`
SET FOREIGN_KEY_CHECKS = 1 ;
DROP SCHEMA IF EXISTS `scans` ;
