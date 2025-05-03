# Step 1: Log in as admin to get a token
$loginBody = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$loginResponse = Invoke-WebRequest -Uri "http://localhost:3000/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
$loginResult = $loginResponse.Content | ConvertFrom-Json
$token = $loginResult.token

Write-Host "Logged in as admin. Token: $token"

# Step 2: Create a new admin account using the token
$createAdminBody = @{
    username = "subadmin"
    email = "subadmin@example.com"
    password = "SubAdmin123!"
} | ConvertTo-Json

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$response = Invoke-WebRequest -Uri "http://localhost:3000/api/auth/create-admin" -Method Post -Body $createAdminBody -Headers $headers
$result = $response.Content | ConvertFrom-Json

Write-Host "Admin creation result: $($response.Content)"

