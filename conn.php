<?php
	$servername = "localhost";
	$dbusername = "root";
	$dbpassword = "root";
	$dbname = "test";
	@$conn=mysql_connect($servername,$dbusername,$dbpassword) or die ("数据库连接失败");
	mysql_select_db($dbname,$conn) or die("数据库访问错误".mysql_error());  