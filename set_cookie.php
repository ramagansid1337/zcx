<?php
// กำหนดค่าสำหรับ cookie
define('COOKIE_NAME', 'dstat_challenge'); // ตั้งชื่อ cookie ให้ตรงกับที่กำหนดใน Go
define('COOKIE_LIFETIME', 86400); // 24 ชั่วโมง เหมือนใน Go

// ตรวจสอบว่ามี POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // รับข้อมูลจาก POST
    $path = isset($_POST['path']) ? $_POST['path'] : '/';
    $challenge_id = isset($_POST['challenge_id']) ? $_POST['challenge_id'] : '';
    $user_verified = isset($_POST['user_verified']) ? $_POST['user_verified'] : false;
    
    // ตรวจสอบความถูกต้องของข้อมูล
    if ($user_verified === 'true' && !empty($challenge_id)) {
        // สร้าง cookie value แบบสุ่ม
        $cookie_value = generateCookieValue();
        
        // บันทึกค่า cookie ในฐานข้อมูลหรือไฟล์หากต้องการ (อาจใช้ Redis, Memcached, ฯลฯ)
        // storeValidCookie($cookie_value, time() + COOKIE_LIFETIME);
        
        // ตั้งค่า cookie แยกตาม path
        setcookie(
            COOKIE_NAME,
            $cookie_value,
            [
                'expires' => time() + COOKIE_LIFETIME,
                'path' => $path, // ตั้งค่า path ตามที่รับมา
                'domain' => $_SERVER['HTTP_HOST'],
                'secure' => true,
                'httponly' => false, // ให้ JavaScript เข้าถึงได้
                'samesite' => 'Lax'
            ]
        );
        
        // ตั้งค่า cookie เพิ่มเติมสำหรับ path อื่นๆ หากต้องการ
        // ตัวอย่าง: ตั้งค่า cookie สำหรับ root path
        setcookie(
            COOKIE_NAME . '_root',
            $cookie_value,
            [
                'expires' => time() + COOKIE_LIFETIME,
                'path' => '/',
                'domain' => $_SERVER['HTTP_HOST'],
                'secure' => true,
                'httponly' => false,
                'samesite' => 'Lax'
            ]
        );
        
        // ส่งสถานะ success
        header('Content-Type: application/json');
        echo json_encode(['status' => 'success', 'message' => 'Cookie set successfully']);
    } else {
        // ถ้าข้อมูลไม่ถูกต้อง
        header('HTTP/1.1 400 Bad Request');
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Invalid verification data']);
    }
    exit;
}

// ฟังก์ชันสร้างค่า cookie แบบสุ่ม
function generateCookieValue() {
    $length = 32;
    $bytes = random_bytes($length);
    return base64_encode($bytes);
}

// ฟังก์ชันบันทึก cookie ในฐานข้อมูล (อาจใช้หรือไม่ก็ได้)
function storeValidCookie($cookie_value, $expiry) {
    // ตัวอย่างการบันทึกใน Redis
    // $redis = new Redis();
    // $redis->connect('127.0.0.1', 6379);
    // $redis->set("valid_cookie:$cookie_value", "1", $expiry - time());
    
    // หรือบันทึกในไฟล์
    $cookies_file = '/tmp/valid_cookies.json';
    $cookies = [];
    
    if (file_exists($cookies_file)) {
        $cookies = json_decode(file_get_contents($cookies_file), true) ?: [];
    }
    
    $cookies[$cookie_value] = $expiry;
    
    // ลบ cookies ที่หมดอายุ
    foreach ($cookies as $value => $exp) {
        if ($exp < time()) {
            unset($cookies[$value]);
        }
    }
    
    file_put_contents($cookies_file, json_encode($cookies));
}

// ถ้าไม่ใช่ POST request ให้แสดงข้อความ error
header('HTTP/1.1 405 Method Not Allowed');
header('Content-Type: application/json');
echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
exit;
?>
