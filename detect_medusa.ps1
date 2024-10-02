function Get-Persistence(){
    Write-Host "[~] Getting CurrentVersion/Run key";
    $baby_lockerz_peristence = Get-ItemProperty -Path HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN -Name BABYLOCKERZ 2>NULL;
    if ($?){ 
        Write-Host "[-] BABYLOCKERZ present in registry, medusa persistence installed (HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN Value:BABYLOCKERZ)" -ForegroundColor red
        Write-Host "[-] Value : ",$baby_lockerz_peristence -ForegroundColor red
    }
    else {
        Write-Host "[+] BABYLOCKERZ not found, no persistence" -ForegroundColor green
    }

}
function Get-PersistenceAllUsers(){
    Write-Host "[~] Getting CurrentVersion/Run key for all users";
    $users = Get-ChildItem -Path Registry::HKEY_USERS 2>NULL
    foreach ($user in $users) {
        $runKeyPath = "Registry::HKEY_USERS\$($user.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $baby_lockerz_peristence = Get-ItemProperty -Path $runKeyPath -Name BABYLOCKERZ 2>NULL ;
        if ($?){
            Write-Host "[-] BABYLOCKERZ present in registry, medusa persistence installed, path: ",$runKeyPath -ForegroundColor red
            Write-Host "[-] Value : ",$baby_lockerz_peristence -ForegroundColor red
        }
        else {
            Write-Host "[+] BABYLOCKERZ not found in : ",$runKeyPath,", no persistence for this user" -ForegroundColor green
        }
    }

}

function Get-CertsAllUsers(){
    Write-Host "[~] Getting Certificates in registry";
    $users = Get-ChildItem -Path Registry::HKEY_USERS 2>NULL
    foreach ($user in $users) {
        $runKeyPath = "Registry::HKEY_USERS\$($user.PSChildName)\Software\PAIDMEMES"
        $public_certificate_in_reg = Get-ItemProperty -Path $runKeyPath -Name PUBLIC 2>NULL;
        $private_certificate_in_reg = Get-ItemProperty -Path $runKeyPath -Name PRIVATE 2>NULL;
        if ($?){
            Write-Host "[-] Medusa certificate detected in registry" -ForegroundColor red;
            Write-Host "[-] Private key : ",$private_certificate_in_reg -ForegroundColor red;
            Write-Host "";
            Write-Host "[-] Public key : ",$public_certificate_in_reg -ForegroundColor red;
            Write-Host "";
            Write-Host "Keep in mind that we need to get the encrypted AES key to decrypt the data" -ForegroundColor red;
        }else{
            Write-Host "[+] No certificate in registry" -ForegroundColor green
        }
    }

}

function Get-RegCertificates(){
    Write-Host "[~] Getting Certificates in registry";
    $public_certificate_in_reg = Get-ItemProperty -Path HKCU:\SOFTWARE\PAIDMEMES -Name PUBLIC 2>NULL;
    $private_certificate_in_reg = Get-ItemProperty -Path HKCU:\SOFTWARE\PAIDMEMES -Name PRIVATE 2>NULL;
    if ($?){
        Write-Host "[-] Medusa certificate detected in registry" -ForegroundColor red
        Write-Host "[-] Private key : ",$private_certificate_in_reg -ForegroundColor red
        Write-Host "";
        Write-Host "[-] Public key : ",$public_certificate_in_reg -ForegroundColor red
        Write-Host "";
        Write-Host "Keep in mind that we need to get the encrypted AES key to decrypt the data" -ForegroundColor red
    }else{
        Write-Host "[+] No certificate in registry" -ForegroundColor green
    }
}

function Get-BurocomPresence(){
    Write-Host "[~] Checking if burocom logged in graphically";
    if (Test-Path -Path "C:/Users/burocom/"){
        Write-Host "[-] Burocom logged on this machine" -ForegroundColor red
    }else{
        Write-Host "[-] Burocom didnt log on this machine" -ForegroundColor green
    }
}

function Get-PayloadPath(){
    Write-Host "[~] Checking if the payload is on the disk";
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        try{
            Write-Host $(Get-ChildItem -Path $_.Root -Recurse -Filter "247_davidhasselhoff_M.exe" -ErrorAction SilentlyContinue) -ForegroundColor red
        }catch{
            Write-Host "[-] Error with a disk";
        }
    }
}

function Check-Medusa(){
    Get-Persistence
    Get-PersistenceAllUsers
    Get-RegCertificates
    Get-CertsAllUsers
    Get-BurocomPresence
    Get-PayloadPath
}

# To run:
# ipmo detect_medusa.ps1
# Check-Medusa

# To clear:
# rm detect_medusa.ps1
# rm NULL