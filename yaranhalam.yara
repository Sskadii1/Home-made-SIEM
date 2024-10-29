rule Loi_HTTP_404_Lap_Lai
{
    meta:
        description = "Phát hiện lỗi HTTP 404 lặp lại, có thể chỉ ra việc quét tài nguyên"
        author = "Nhat Linh"
        date = "2024-10-30"
    strings:
        $error_404 = "404"
    condition:
        // Phát hiện nếu có nhiều lỗi 404 trong một khoảng thời gian ngắn
        // Giả sử có một hệ thống phân tích log hỗ trợ điều này, có thể dùng
        // #error_404 > 5 để chỉ số lần truy cập lỗi 404 lặp lại nhiều lần
        // Thực tế cần điều chỉnh dựa trên cách cấu hình và triển khai SIEM của bạn
        #error_404 > 5
}

rule Truy_Cap_Den_Endpoint_Nhay_Cam
{
    meta:
        description = "Phát hiện truy cập đến các endpoint nhạy cảm (admin, login, config)"
        author = "Nhat Linh"
        date = "2024-10-30"
    strings:
        $admin = "/admin"
        $login = "/login"
        $config = "/config"
    condition:
        any of them
}

rule Phuong_Thuc_HTTP_Bat_Thuong
{
    meta:
        description = "Phát hiện các phương thức HTTP bất thường (PUT, DELETE)"
        author = "Nhat Linh"
        date = "2024-10-30"
    strings:
        $put = "PUT"
        $delete = "DELETE"
    condition:
        any of them
}

rule IP_Truy_Cap_Lap_Lai
{
    meta:
        description = "Phát hiện truy cập lặp lại từ một địa chỉ IP, chỉ ra hành vi đáng ngờ"
        author = "Nhat Linh"
        date = "2024-10-30"
    strings:
        $ip_dang_nghi = "123.456.789.0" // Thay thế với IP thực tế hoặc mẫu regex
    condition:
        // Tùy vào cấu trúc và các công cụ log hiện tại, có thể dùng
        // Các biểu thức regex hoặc số lần truy cập từ IP này để tùy chỉnh
        // Để phát hiện hành vi brute force, dò mật khẩu, hoặc truy cập bất thường
        #ip_dang_nghi > 10
}

rule Loi_HTTP_500_Lap_Lai
{
    meta:
        description = "Phát hiện lỗi HTTP 500, chỉ ra có thể tấn công thử nghiệm trên hệ thống"
        author = "Nhat Linh"
        date = "2024-10-30"
    strings:
        $error_500 = "500"
    condition:
        #error_500 > 3
}
