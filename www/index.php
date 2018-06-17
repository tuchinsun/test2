<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
        <title>WWW</title>
  </head>
        <body>
                <h2>Hello world!</h2>

<?php

        date_default_timezone_set("Europe/Kiev");
        echo 'Time: ', date("H:i:s"), '<br />';
        echo 'Hostname: ', gethostname();
?>