/*
Navicat MySQL Data Transfer

Source Server         : localhost_3306
Source Server Version : 50553
Source Host           : localhost:3306
Source Database       : test

Target Server Type    : MYSQL
Target Server Version : 50553
File Encoding         : 65001

Date: 2017-07-17 21:57:55
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for admin
-- ----------------------------
DROP TABLE IF EXISTS `admin`;
CREATE TABLE `admin` (
  `id` int(3) NOT NULL AUTO_INCREMENT,
  `user` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `pwd` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- ----------------------------
-- Records of admin
-- ----------------------------
INSERT INTO `admin` VALUES ('1', 'admin', '3f230640b78d7e71ac5514e57935eb69');

-- ----------------------------
-- Table structure for sqltest
-- ----------------------------
DROP TABLE IF EXISTS `sqltest`;
CREATE TABLE `sqltest` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(100) CHARACTER SET utf8 NOT NULL DEFAULT '',
  `content` text CHARACTER SET utf8 NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;

-- ----------------------------
-- Records of sqltest
-- ----------------------------
INSERT INTO `sqltest` VALUES ('1', '第一个', '这是ID=1的数据\r\n1111111111111111111111111111111111111111');
INSERT INTO `sqltest` VALUES ('2', '第二个', '这是ID=2的数据\r\n2222222222222222222222222222222222222222');
INSERT INTO `sqltest` VALUES ('3', '第三个', '这是ID=3的数据\r\n3333333333333333333333333333333333333333');
