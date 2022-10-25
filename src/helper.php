<?php


if (!function_exists('jwt_create')) {
    function jwt_create(string $identification,$data = [])
    {
        return \Zhang003\Jwt\Jwt::create($identification,$data);
    }
}
if (!function_exists('jwt_verify')) {
    function jwt_verify($token = null)
    {
        return \Zhang003\Jwt\Jwt::verify($token);
    }
}
if (!function_exists('jwt_delete')) {
    function jwt_delete($identification = null)
    {
        if ($identification){
            return \Zhang003\Jwt\Jwt::delete($identification);
        }
        return false;
    }
}

if (!function_exists('jwt_realIp')) {
    function jwt_realIp()
    {
        return \Zhang003\Jwt\Jwt::getIp();
    }
}