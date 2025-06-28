<?php
session_start();


$servername = "localhost"; 
$username = "root";        
$password = "";            
$dbname = "blogmaster_db"; 


$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die(json_encode(["success" => false, "message" => "Connection failed: " . $conn->connect_error]));
}


header('Content-Type: application/json');


$action = $_GET['action'] ?? $_POST['action'] ?? '';


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';

    switch ($action) {
        case 'register':
            registerUser($input);
            break;
        case 'login':
            loginUser($input);
            break;
        case 'logout':
            logoutUser();
            break;
        case 'create_post':
            createPost($input);
            break;
        case 'update_post':
            updatePost($input);
            break;
        case 'delete_post':
            deletePost($input);
            break;
        case 'add_comment':
            addComment($input);
            break;
        case 'increment_view':
            incrementView($input);
            break;
        default:
            echo json_encode(["success" => false, "message" => "Unknown POST action."]);
            break;
    }
} 

else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    switch ($action) {
        case 'check_auth':
            checkAuth();
            break;
        case 'get_posts':
            getPosts($_GET['search'] ?? '', $_GET['tag'] ?? '', $_GET['sort'] ?? '');
            break;
        case 'get_single_post':
            getSinglePost($_GET['id'] ?? 0);
            break;
        case 'get_trending_posts':
            getTrendingPosts();
            break;
        case 'get_all_tags':
            getAllTags();
            break;
        case 'get_user_posts':
            getUserPosts($_GET['author_id'] ?? 0);
            break;
        case 'get_related_posts':
            getRelatedPosts($_GET['current_post_id'] ?? 0, $_GET['tags'] ?? '', $_GET['limit'] ?? 5);
            break;
        default:
            echo json_encode(["success" => false, "message" => "Unknown GET action."]);
            break;
    }
}

$conn->close();



function registerUser($data) {
    global $conn;
    $username = $conn->real_escape_string($data['username'] ?? '');
    $email = $conn->real_escape_string($data['email'] ?? '');
    $password = $conn->real_escape_string($data['password'] ?? '');

    if (empty($username) || empty($email) || empty($password)) {
        echo json_encode(["success" => false, "message" => "All fields are required."]);
        return;
    }

   
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? OR username = ?");
    $stmt->bind_param("ss", $email, $username);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        echo json_encode(["success" => false, "message" => "Email or username already exists."]);
        $stmt->close();
        return;
    }
    $stmt->close();

    $created_at = date('Y-m-d H:i:s');
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $email, $password, $created_at);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "Registration successful!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Registration failed: " . $stmt->error]);
    }
    $stmt->close();
}

function loginUser($data) {
    global $conn;
    $email = $conn->real_escape_string($data['email'] ?? '');
    $password = $conn->real_escape_string($data['password'] ?? '');

    if (empty($email) || empty($password)) {
        echo json_encode(["success" => false, "message" => "Email and password are required."]);
        return;
    }

    $stmt = $conn->prepare("SELECT id, username, email, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        if ($password === $user['password']) { 
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            echo json_encode(["success" => true, "message" => "Login successful!", "user" => ["id" => $user['id'], "username" => $user['username']]]);
        } else {
            echo json_encode(["success" => false, "message" => "Invalid email or password."]);
        }
    } else {
        echo json_encode(["success" => false, "message" => "Invalid email or password."]);
    }
    $stmt->close();
}

function logoutUser() {
    session_unset();
    session_destroy();
    echo json_encode(["success" => true, "message" => "Logged out successfully!"]);
}

function checkAuth() {
    if (isset($_SESSION['user_id']) && isset($_SESSION['username'])) {
        echo json_encode(["success" => true, "user" => ["id" => $_SESSION['user_id'], "username" => $_SESSION['username']]]);
    } else {
        echo json_encode(["success" => false, "user" => null]);
    }
}

function getPosts($search, $tag, $sort) {
    global $conn;
    $sql = "SELECT id, title, content, tags, image, author, author_id, created_at, updated_at, views, comments FROM posts WHERE 1=1";
    $params = [];
    $types = "";

   
    if (!empty($search)) {
        $search_term = '%' . $search . '%';
        $sql .= " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)";
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
        $types .= "sss";
    }

    
    if (!empty($tag)) {
        $tag_term = '%' . $tag . '%';
        $sql .= " AND tags LIKE ?";
        $params[] = $tag_term;
        $types .= "s";
    }

    
    switch ($sort) {
        case 'oldest':
            $sql .= " ORDER BY created_at ASC";
            break;
        case 'most_viewed':
            $sql .= " ORDER BY views DESC";
            break;
        default: 
            $sql .= " ORDER BY created_at DESC";
            break;
    }

    $stmt = $conn->prepare($sql);

    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    $posts = [];
    while ($row = $result->fetch_assoc()) {
        $posts[] = $row;
    }
    $stmt->close();
    echo json_encode(["success" => true, "posts" => $posts]);
}

function getSinglePost($id) {
    global $conn;
    $id = (int)$id; 
    $stmt = $conn->prepare("SELECT id, title, content, tags, image, author, author_id, created_at, updated_at, views, comments FROM posts WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $post = $result->fetch_assoc();
        echo json_encode(["success" => true, "post" => $post]);
    } else {
        echo json_encode(["success" => false, "message" => "Post not found."]);
    }
    $stmt->close();
}

function incrementView($data) {
    global $conn;
    $id = (int)($data['id'] ?? 0);

    if ($id <= 0) {
        echo json_encode(["success" => false, "message" => "Invalid post ID."]);
        return;
    }

    $stmt = $conn->prepare("UPDATE posts SET views = views + 1 WHERE id = ?");
    $stmt->bind_param("i", $id);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "View count incremented."]);
    } else {
        echo json_encode(["success" => false, "message" => "Failed to increment view: " . $stmt->error]);
    }
    $stmt->close();
}

function getTrendingPosts() {
    global $conn;
    $sql = "SELECT id, title, views FROM posts ORDER BY views DESC LIMIT 5";
    $result = $conn->query($sql);
    $posts = [];
    while ($row = $result->fetch_assoc()) {
        $posts[] = $row;
    }
    echo json_encode(["success" => true, "posts" => $posts]);
}

function getAllTags() {
    global $conn;
    $sql = "SELECT tags FROM posts";
    $result = $conn->query($sql);
    $all_tags = [];
    while ($row = $result->fetch_assoc()) {
        $tags_str = $row['tags'];
        if (!empty($tags_str)) {
            $tags_arr = array_map('trim', explode(',', $tags_str));
            $all_tags = array_merge($all_tags, $tags_arr);
        }
    }
    $unique_tags = array_values(array_unique($all_tags));
    sort($unique_tags); 
    echo json_encode(["success" => true, "tags" => $unique_tags]);
}

function getUserPosts($author_id) {
    global $conn;
    
    if (!isset($_SESSION['user_id']) || $_SESSION['user_id'] != $author_id) {
        echo json_encode(["success" => false, "message" => "Unauthorized access."]);
        return;
    }

    $author_id = (int)$author_id;
    $stmt = $conn->prepare("SELECT id, title, content, tags, image, author, created_at, updated_at, views, comments FROM posts WHERE author_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $author_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $posts = [];
    while ($row = $result->fetch_assoc()) {
        $posts[] = $row;
    }
    $stmt->close();
    echo json_encode(["success" => true, "posts" => $posts]);
}

function createPost($data) {
    global $conn;
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["success" => false, "message" => "User not logged in."]);
        return;
    }

    $title = $conn->real_escape_string($data['title'] ?? '');
    $content = $conn->real_escape_string($data['content'] ?? '');
    $tags = $conn->real_escape_string($data['tags'] ?? '');
    $image = $conn->real_escape_string($data['image'] ?? '');
    $author = $conn->real_escape_string($data['author'] ?? $_SESSION['username']);
    $author_id = (int)$_SESSION['user_id'];
    $created_at = date('Y-m-d H:i:s');
    $updated_at = $created_at;
    $views = 0;
    $comments = json_encode([]); 

    if (empty($title) || empty($content)) {
        echo json_encode(["success" => false, "message" => "Title and content are required."]);
        return;
    }

    $stmt = $conn->prepare("INSERT INTO posts (title, content, tags, image, author, author_id, created_at, updated_at, views, comments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssissss", $title, $content, $tags, $image, $author, $author_id, $created_at, $updated_at, $views, $comments);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "Post published successfully!", "id" => $conn->insert_id]);
    } else {
        echo json_encode(["success" => false, "message" => "Failed to create post: " . $stmt->error]);
    }
    $stmt->close();
}

function updatePost($data) {
    global $conn;
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["success" => false, "message" => "User not logged in."]);
        return;
    }

    $id = (int)($data['id'] ?? 0);
    $title = $conn->real_escape_string($data['title'] ?? '');
    $content = $conn->real_escape_string($data['content'] ?? '');
    $tags = $conn->real_escape_string($data['tags'] ?? '');
    $image = $conn->real_escape_string($data['image'] ?? '');
    $author_id = (int)$_SESSION['user_id'];
    $updated_at = date('Y-m-d H:i:s');

    if ($id <= 0 || empty($title) || empty($content)) {
        echo json_encode(["success" => false, "message" => "Invalid data for update."]);
        return;
    }

    
    $check_stmt = $conn->prepare("SELECT author_id FROM posts WHERE id = ?");
    $check_stmt->bind_param("i", $id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    if ($check_result->num_rows == 0 || $check_result->fetch_assoc()['author_id'] != $author_id) {
        echo json_encode(["success" => false, "message" => "Unauthorized: You do not own this post."]);
        $check_stmt->close();
        return;
    }
    $check_stmt->close();

    $stmt = $conn->prepare("UPDATE posts SET title = ?, content = ?, tags = ?, image = ?, updated_at = ? WHERE id = ? AND author_id = ?");
    $stmt->bind_param("sssssii", $title, $content, $tags, $image, $updated_at, $id, $author_id);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "Post updated successfully!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Failed to update post: " . $stmt->error]);
    }
    $stmt->close();
}

function deletePost($data) {
    global $conn;
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["success" => false, "message" => "User not logged in."]);
        return;
    }

    $id = (int)($data['id'] ?? 0);
    $author_id = (int)$_SESSION['user_id'];

    if ($id <= 0) {
        echo json_encode(["success" => false, "message" => "Invalid post ID."]);
        return;
    }

    
    $check_stmt = $conn->prepare("SELECT author_id FROM posts WHERE id = ?");
    $check_stmt->bind_param("i", $id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    if ($check_result->num_rows == 0 || $check_result->fetch_assoc()['author_id'] != $author_id) {
        echo json_encode(["success" => false, "message" => "Unauthorized: You do not own this post."]);
        $check_stmt->close();
        return;
    }
    $check_stmt->close();

    $stmt = $conn->prepare("DELETE FROM posts WHERE id = ? AND author_id = ?");
    $stmt->bind_param("ii", $id, $author_id);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "Post deleted successfully!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Failed to delete post: " . $stmt->error]);
    }
    $stmt->close();
}

function addComment($data) {
    global $conn;
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["success" => false, "message" => "User not logged in."]);
        return;
    }

    $post_id = (int)($data['post_id'] ?? 0);
    $content = $conn->real_escape_string($data['content'] ?? '');
    $author = $conn->real_escape_string($data['author'] ?? $_SESSION['username']);
    $author_id = (int)$_SESSION['user_id'];
    $created_at = date('Y-m-d H:i:s');

    if ($post_id <= 0 || empty($content)) {
        echo json_encode(["success" => false, "message" => "Invalid comment data."]);
        return;
    }

   
    $stmt = $conn->prepare("SELECT comments FROM posts WHERE id = ?");
    $stmt->bind_param("i", $post_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $current_comments = json_decode($row['comments'] ?? '[]', true);
        if (!is_array($current_comments)) { 
            $current_comments = [];
        }

        
        $new_comment_id = count($current_comments) > 0 ? max(array_column($current_comments, 'id')) + 1 : 1;

        $new_comment = [
            'id' => $new_comment_id,
            'content' => $content,
            'author' => $author,
            'author_id' => $author_id,
            'created_at' => $created_at
        ];
        $current_comments[] = $new_comment;
        $updated_comments_json = json_encode($current_comments);

        $update_stmt = $conn->prepare("UPDATE posts SET comments = ? WHERE id = ?");
        $update_stmt->bind_param("si", $updated_comments_json, $post_id);
        if ($update_stmt->execute()) {
            echo json_encode(["success" => true, "message" => "Comment added successfully!"]);
        } else {
            echo json_encode(["success" => false, "message" => "Failed to add comment: " . $update_stmt->error]);
        }
        $update_stmt->close();
    } else {
        echo json_encode(["success" => false, "message" => "Post not found."]);
    }
    $stmt->close();
}

function getRelatedPosts($current_post_id, $tags_string, $limit) {
    global $conn;
    $current_post_id = (int)$current_post_id;
    $limit = (int)$limit;
    $tags_array = array_map('trim', explode(',', $tags_string));
    $tags_array = array_filter($tags_array);

    if (empty($tags_array)) {
        echo json_encode(["success" => true, "posts" => []]);
        return;
    }

    
    $like_clauses = [];
    $params = [];
    $types = "";

    foreach ($tags_array as $tag) {
        $like_clauses[] = "tags LIKE ?";
        $params[] = '%' . $tag . '%';
        $types .= "s";
    }
    $where_clause = implode(' OR ', $like_clauses);

    $sql = "SELECT id, title, views FROM posts WHERE id != ? AND ({$where_clause}) ORDER BY views DESC LIMIT ?";
    
    
    array_unshift($params, $current_post_id);
    array_push($params, $limit);
    $types = "i" . $types . "i";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    $posts = [];
    while ($row = $result->fetch_assoc()) {
        $posts[] = $row;
    }
    $stmt->close();
    echo json_encode(["success" => true, "posts" => $posts]);
}

?>
