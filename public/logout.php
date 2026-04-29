<?php
/**
 * Aegis Auth - Logout
 */

require_once __DIR__ . '/../app/auth.php';
logoutUser();
header('Location: login.php');
exit;
