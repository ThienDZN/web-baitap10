-- ===========================================================================
-- Bai04-JWT-Nimbus - thiet lap database MySQL/MariaDB
--
-- Chay bang mot tai khoan co quyen (thuong la root):
--   mysql -u root -p < docs/setup-mysql.sql
--
-- Sau do chay ung dung voi profile mysql:
--   APP_DB_USERNAME='thien' APP_DB_PASSWORD='mat-khau-cua-ban' \
--     mvn spring-boot:run -Dspring-boot.run.profiles=mysql
-- ===========================================================================

-- 1. Tao database rieng cho bai JWT.
--    Dat ten 'jwt_springboot3' theo bai giang, KHONG dung ten 'thien' (database dung chung
--    cua cac du an khac) de bang 'users' khong dung do voi bang cua du an khac.
CREATE DATABASE IF NOT EXISTS `jwt_springboot3`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- 2. Cap quyen cho tai khoan ung dung.
--    Doi 'mat-khau-cua-ban' thanh mat khau that truoc khi chay.
--    Neu tai khoan 'thien' da ton tai va ban chi muon cap them quyen,
--    bo qua dong CREATE USER va chi chay 2 dong GRANT.
CREATE USER IF NOT EXISTS 'thien'@'localhost' IDENTIFIED BY 'mat-khau-cua-ban';
GRANT ALL PRIVILEGES ON `jwt_springboot3`.* TO 'thien'@'localhost';
FLUSH PRIVILEGES;

-- 3. Kiem tra.
SHOW DATABASES LIKE 'jwt_springboot3';
SHOW GRANTS FOR 'thien'@'localhost';

-- ===========================================================================
-- Ghi chu:
--  - Bang 'users' KHONG can tao truoc. Hibernate voi
--    spring.jpa.hibernate.ddl-auto=update se tu tao khi ung dung khoi dong.
--  - Neu khong muon cap quyen CREATE cho tai khoan ung dung, hay tao database
--    bang tay (muc 1) truoc roi moi cap quyen (muc 2).
--  - XAMPP: mo phpMyAdmin hoac dung
--      /opt/lampp/bin/mysql -u root -p < docs/setup-mysql.sql
-- ===========================================================================
