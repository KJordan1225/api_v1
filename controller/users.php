<?php

require_once('db.php');
require_once('../model/response.php');

try{
  $writeDB = DB::connectWriteDB();
  // $readDB = DB::connectReadDB();
}
catch(PDOException $ex){
  error_log("Connection error - ".$ex,0);
  $response = new Response();
  $response->setHttpStatusCode(500);
  $response->setSuccess(false);
  $response->addMessage("Database connection error");
  $response->send();
  exit();
}

if($_SERVER['REQUEST_METHOD'] !== 'POST'){
  $response = new Response();
  $response->setHttpStatusCode(405);
  $response->setSuccess(false);
  $response->addMessage("Request method not allowed");
  $response->send();
  exit();
}

if($_SERVER['HTTP_CONTENT_TYPE'] !== 'application/json'){
  $response = new Response();
  $response->setHttpStatusCode(400);
  $response->setSuccess(false);
  $response->addMessage("Content header not set to JSON");
  $response->send();
  exit;
}

$rawPOSTData = file_get_contents('php://input');

if(!$jsonData = json_decode($rawPOSTData)){
  $response = new Response();
  $response->setHttpStatusCode(400);
  $response->setSuccess(false);
  $response->addMessage("Request body is not valid JSON");
  $response->send();
  exit;
}

if(!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)){
  $response = new Response();
  $response->setHttpStatusCode(400);
  $response->setSuccess(false);
  (!isset($jsonData->fullname) ? $response->addMessage("Full name not supplied") : false);
  (!isset($jsonData->username) ? $response->addMessage("Username not supplied") : false);
  (!isset($jsonData->password) ? $response->addMessage("Password not supplied") : false);
  $response->send();
  exit;
}

if(strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255 || strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255){
  $response = new Response();
  $response->setHttpStatusCode(400);
  $response->setSuccess(false);
  (strlen($jsonData->fullname) < 1 ? $response->addMessage("Full name cannot be blank") : false);
  (strlen($jsonData->fullname) > 255 ? $response->addMessage("Full name cannot be more than 255 chareacters") : false);
  (strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank") : false);
  (strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be more than 255 chareacters") : false);
  (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : false);
  (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be more than 255 chareacters") : false);
  $response->send();
  exit;
}

$fullname = trim($jsonData->fullname);
$username = trim($jsonData->username);
$password = $jsonData->password;

try{

  $query = $writeDB->prepare("select id from tlbusers where username = :username");
  $query->bindParam(':username', $username, PDO::PARAM_STR);
  $query->execute();

  // print_r("after select stmt executed");

  $rowCount = $query->rowCount();

  if($rowCount > 0){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Username already exists");
    $response->send();
    exit;
  }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $query = $writeDB->prepare("insert into tlbusers (fullname, username, password) values (:fullname, :username, :password)");
    $query->bindParam(':fullname',$fullname, PDO::PARAM_STR);
    $query->bindParam(':username',$username, PDO::PARAM_STR);
    $query->bindParam(':password',$hashed_password, PDO::PARAM_STR);
    $query->execute();

    $rowCount = $query->rowCount();

    if($rowCount === 0){
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("There was a problem creating the new user - please try again");
      $response->send();
      exit;
    }

    $lastUserID = $writeDB->lastInsertId();

    $returnData = array();
    $returnData['user_id'] = $lastUserID;
    $returnData['fullname'] = $fullname;
    $returnData['username'] = $username;

    $response = new Response();
    $response->setHttpStatusCode(200);
    $response->setSuccess(true);
    $response->addMessage("User created");
    $response->setData($returnData);
    $response->send();
    exit;


}
catch(PDOException $ex){
  error_log("Connection error - ".$ex,0);
  $response = new Response();
  $response->setHttpStatusCode(500);
  $response->setSuccess(false);
  $response->addMessage("Problem creating new user - please try again");
  $response->send();
  exit();
}

 ?>
