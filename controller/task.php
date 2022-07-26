<?php

date_default_timezone_set('America/New_York');

require_once('db.php');
require_once('../model/response.php');
require_once('../model/Task.php');

try{
  $writeDB = DB::connectWriteDB();
  $readDB = DB::connectReadDB();
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

// begin auth description

if(!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1){
  $response = new Response();
  $response->setHttpStatusCode(401);
  $response->setSuccess(false);
  (!isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage("Access token is missing from the header") : false);
  (strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage("Access token cannot be blank") : false);
  $response->send();
  exit;
}

$accesstoken = $_SERVER['HTTP_AUTHORIZATION'];

try{
  $query = $writeDB->prepare("select userid, accesstokenexpiry, useractive, loginattempts from tblsessions_1, tlbusers where tblsessions_1.userid = tlbusers.id and accesstoken = :accestoken");
  $query->bindParam(':accestoken', $accesstoken, PDO::PARAM_STR);
  $query->execute();

  $rowCount = $query->rowCount();

  if($rowCount === 0){
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("Invalid access token");
    $response->send();
    exit();
  }

  $row = $query->fetch(PDO::FETCH_ASSOC);

  $returned_userid = $row['userid'];
  $returned_accesstokenexpiry = $row['accesstokenexpiry'];
  $returned_useractive = $row['useractive'];
  $returned_loginattempts = $row['loginattempts'];

  if($returned_useractive !== 'Y'){
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("User account is inactive");
    $response->send();
    exit();
  }

  if($returned_loginattempts >= 3){
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("User account is currently locked out");
    $response->send();
    exit();
  }

// print_r($returned_accesstokenexpiry);
// print_r("<br>");
// print_r(strftime('%Y-%m-%d %H:%M',time()));

  if(strtotime($returned_accesstokenexpiry) < time()) {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("Access token has expired");
    $response->send();
    exit;
  }
}
catch(PDOException $ex){
  $response = new Response();
  $response->setHttpStatusCode(500);
  $response->setSuccess(false);
  $response->addMessage("There was an issue authenticating - please try again");
  // $response->addMessage($ex->getMessage());
  $response->send();
  exit();
}

// end auth script


// GET single post from dataabase.
if(array_key_exists("taskid",$_GET)){
  $taskid = $_GET["taskid"];

  if($taskid =='' || !is_numeric($taskid)){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Task ID cannot be blank and must be numeric");
    $response->send();
    exit;
  }

  if($_SERVER['REQUEST_METHOD'] === 'GET'){

    try {

      $query = $readDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where id = :taskid and userid = :userid");
      $query->bindParam(':taskid',$taskid, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("Task not found");
        $response->send();
        exit;
      }

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->send();
      exit;
    }
    catch(TaskException $ex){
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage($ex->getMessage());
      $response->send();
      exit;
    }
    catch(PDOException $ex){
      error_log("Database query error - ".$ex,0);
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to get Task");
      $response->send();
      exit();
    }
  }
  elseif($_SERVER['REQUEST_METHOD'] === 'DELETE'){

    try {
      $query = $readDB->prepare("delete from tbltasks where id = :taskid and userid = :userid");
      $query->bindParam(':taskid',$taskid, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("Task not found");
        $response->send();
        exit;
      }

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->addMessage("Task deleted");
      $response->send();
      exit;

    }
    catch(PDOException $ex){
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to delete task");
      $response->send();
      exit;
    }
  }
  elseif($_SERVER['REQUEST_METHOD'] === 'PATCH'){
    // PATCH (update) selected task in database

    try {

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

      $queryFields = "";

      $title_updated = false;
      $description_updated = false;
      $deadline_updated = false;
      $completed_updated = false;

      if(isset($jsonData->title)){
        $title_updated = true;
        $queryFields .= "title = :title, ";
      }

      if(isset($jsonData->description)){
        $description_updated = true;
        $queryFields .= "description = :description, ";
      }

      if(isset($jsonData->deadline)){
        $deadline_updated = true;
        $queryFields .= "deadline = STR_TO_DATE(:deadline,'%m/%d/%Y %H:%i'), ";
      }

      if(isset($jsonData->completed)){
        $completed_updated = true;
        $queryFields .= "completed = :completed, ";
      }

      $queryFields = rtrim($queryFields, ", ");

      if($title_updated === false && $description_updated === false && $deadline_updated === false && $completed_updated === false){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("No update fields provided");
        $response->send();
        exit;
      }

      $query = $writeDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where id = :taskid and userid = :userid");
      $query->bindParam(':taskid',$taskid, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("No task found to update");
        $response->send();
        exit;
      }

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          // $tasksArray[] = $task->returnTaskAsArray();
      }

      $queryString = "update tbltasks set ".$queryFields. " where id = :taskid";
      $query = $writeDB->prepare($queryString);

      if($title_updated === true){
        $task->setTitle($jsonData->title);
        $up_title = $task->getTitle();
        $query->bindParam('title',$up_title,PDO::PARAM_STR);
      }

      if($description_updated === true){
        $task->setDescription($jsonData->description);
        $up_description = $task->getDescription();
        $query->bindParam('description',$up_description,PDO::PARAM_STR);
      }

      if($deadline_updated === true){
        $task->setDeadline($jsonData->deadline);
        $up_deadline = $task->getDeadline();
        $query->bindParam('deadline',$up_deadline,PDO::PARAM_STR);
      }

      if($completed_updated === true){
        $task->setCompleted($jsonData->completed);
        $up_completed = $task->getCompleted();
        $query->bindParam('completed',$up_completed,PDO::PARAM_STR);
      }

      // print_r("update task completed ".$queryString."<br>");
      // exit;

      $query->bindParam('taskid',$taskid, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Task not updated");
        $response->send();
        exit;
      }

      $query = $writeDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where id = :taskid and userid = :userid");
      $query->bindParam(':taskid',$taskid, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("No task found after update");
        $response->send();
        exit;
      }

      $tasksArray = array();

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }


      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->addMessage("Task updated");
      $response->send();
      exit;
    }
    catch(TaskException $ex){
      $response = new Response();
      $response->setHttpStatusCode(400);
      $response->setSuccess(false);
      $response->addMessage($ex->getMessage());
      $response->send();
      exit;
    }
    catch(PDOException $ex){
      error_log("Database query error - ".$ex,0);
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to update Task - check your data for errors");
      $response->send();
      exit();
    }


  }
  else {
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed");
    $response->send();
    exit();
  }

}

elseif(array_key_exists("completed",$_GET)){
// GET all completed or not completed tasks from database.
  $completed = $_GET['completed'];

  if($completed !== 'Y' && $completed !== 'N') {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Completed filter must be Y or N");
    $response->send();
    exit;
  }

  if($_SERVER['REQUEST_METHOD'] === 'GET'){

    try {

      $query = $readDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where completed = :completed and userid = :userid");
      $query->bindParam(':completed',$completed,PDO::PARAM_STR);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      $tasksArray = array();

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->send();
      exit;
    }
    catch(TaskException $ex) {
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage($ex->getMessage());
      $response->send();
      exit;
    }
    catch(PDOException $ex) {
      error_log("Database query error - ".$ex,0);
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to get tasks");
      $response->send();
      exit;
    }

  }
  else {
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed");
    $response->send();
    exit;
  }
}
elseif(array_key_exists("page",$_GET)){
// GET page of 20 tasks from database
  if($_SERVER['REQUEST_METHOD'] === 'GET'){

    $page = $_GET['page'];

    if($page == '' || !is_numeric($page) || $page < 1){
      $response = new Response();
      $response->setHttpStatusCode(400);
      $response->setSuccess(false);
      $response->addMessage("Page number cannot be blank or must be numeric and greater than 0");
      $response->send();
      exit;
    }

    $limitPerPage = 20;

    try {

      $query = $readDB->prepare("select count(id) as totalNoOfTasks from tbltasks where userid = :userid");
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $row = $query->fetch(PDO::FETCH_ASSOC);

      $tasksCount = intval($row['totalNoOfTasks']);

      $numOfPages = ceil($tasksCount / $limitPerPage);

      if($numOfPages == 0){
        $numOfPages = 1;
      }

      if($page > $numOfPages){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("Page not found");
        $response->send();
        exit;
      }

      $offset = ($page == 1 ? 0 : ($limitPerPage*($page-1)));

      $query = $readDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where userid = :userid limit :pgLimit offset :offset");
      $query->bindParam(':pgLimit',$limitPerPage,PDO::PARAM_INT);
      $query->bindParam(':offset',$offset,PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      $tasksArray = array();

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['total_rows'] = $tasksCount;
      $returnData['total_pages'] = $numOfPages;
      ($page < $numOfPages) ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false;
      ($page > 1) ? $returnData['has_previous_page'] = true : $returnData['has_previous_page'] = false;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->send();
      exit;
    }
    catch(TaskException $ex) {
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage($ex->getMessage());
      $response->send();
      exit;
    }
    catch(PDOException $ex) {
      error_log("Database query error - ".$ex,0);
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to get tasks");
      $response->send();
      exit;
    }

  }
  else {
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed");
    $response->send();
    exit;
  }

}
elseif(empty($_GET))
// GET all tasks from database
  if($_SERVER['REQUEST_METHOD'] == 'GET'){

    try {
      $query = $readDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where userid = :userid");
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      // if($rowCount === 0){
      //   $response = new Response();
      //   $response->setHttpStatusCode(404);
      //   $response->setSuccess(false);
      //   $response->addMessage("No tasks found");
      //   $response->send();
      //   exit;
      // }
      $tasksArray = array();

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(200);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->send();
      exit;
    }
    catch(TaskException $ex){
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage($ex->getMessage());
      $response->send();
      exit;
    }
    catch(PDOException $ex){
      error_log("Database query error - ".$ex,0);
      $response = new Response();
      $response->setHttpStatusCode(500);
      $response->setSuccess(false);
      $response->addMessage("Failed to get Tasks");
      $response->send();
      exit();
    }

} elseif ($_SERVER['REQUEST_METHOD'] == 'POST'){
// CREATE task to insert into database
  // print_r($_SERVER);

  try {


      if($_SERVER['HTTP_CONTENT_TYPE'] !== 'application/json'){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Content type header is not set to JSON");
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

      if(!isset($jsonData->title) || !isset($jsonData->completed)){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        !isset($jsonData->title) ? $response->addMessage("Title field is mandatory and must be provided") : false;
        !isset($jsonData->completed) ? $response->addMessage("Completed field is mandatory and must be provided") : false;
        $response->send();
        exit;
      }

      $newTask = new Task(null,$jsonData->title, (isset($jsonData->description) ? $jsonData->description : null),  (isset($jsonData->deadline) ? $jsonData->deadline : null), $jsonData->completed);

      $title = $newTask->getTitle();
      $description = $newTask->getDescription();
      $deadline = $newTask->getDeadline();
      $completed = $newTask->getCompleted();

      $query = $writeDB->prepare("insert into tbltasks (title, description, deadline, completed, userid) values (:title, :description, STR_TO_DATE(:deadline,'%m/%d/%Y %H:%i'), :completed, :userid)");
      $query->bindParam(':title', $title, PDO::PARAM_STR);
      $query->bindParam(':description', $description, PDO::PARAM_STR);
      $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
      $query->bindParam(':completed', $completed, PDO::PARAM_STR);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Failed to create task");
        $response->send();
        exit;
      }

      $lastTaskID = $writeDB->lastInsertId();

      $query = $writeDB->prepare("select id, title, description, DATE_FORMAT(deadline, '%m/%d/%Y %H:%i') as deadline, completed from tbltasks where id = :taskid and userid = :userid");
      $query->bindParam(':taskid',$lastTaskID, PDO::PARAM_INT);
      $query->bindParam(':userid',$returned_userid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0){
        $response = new Response();
        $response->setHttpStatusCode(404);
        $response->setSuccess(false);
        $response->addMessage("Failed to retrieve task after creation");
        $response->send();
        exit;
      }

      while($row = $query->fetch(PDO::FETCH_ASSOC)){
          $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
          $tasksArray[] = $task->returnTaskAsArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $tasksArray;

      $response = new Response();
      $response->setHttpStatusCode(201);
      $response->setSuccess(true);
      $response->toCache(true);
      $response->setData($returnData);
      $response->addMessage("Task created");
      $response->send();
      exit;
  }
  catch(TaskException $ex){
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage($ex->getMessage());
    $response->send();
    exit;
  }
  catch(PDOException $ex){
    error_log("Database query error - ".$ex,0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Failed to insert task into database - check submitted data for errors");
    $response->send();
    exit;
  }

} else {
  $response = new Response();
  $response->setHttpStatusCode(404);
  $response->setSuccess(false);
  $response->addMessage("Endpoint not found");
  $response->send();
  exit;

}


?>
