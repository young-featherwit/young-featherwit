<?php
	$servername = "localhost";
	$dbusername = "root";
	$dbpassword = "root";
	$dbname = "test";
	@$conn=mysql_connect($servername,$dbusername,$dbpassword) or die ("���ݿ�����ʧ��");
	mysql_select_db($dbname,$conn) or die("���ݿ���ʴ���".mysql_error());  