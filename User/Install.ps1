param(
$team_id,
$key
)

while(!(Test-NetConnection Google.com).PingSucceeded){
    Start-Sleep -Seconds 1
}

if (!(Get-WmiObject Win32_VideoController | Where-Object name -like "VB-Audio Virtual Cable")) {
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\Users\$env:USERNAME\Downloads\VBCable.zip")
    New-Item -Path "C:\Users\$env:Username\Downloads\VBCable" -ItemType Directory| Out-Null
    Expand-Archive -Path "C:\Users\$env:USERNAME\Downloads\VBCable.zip" -DestinationPath "C:\Users\$env:USERNAME\Downloads\VBCable"
    $pathToCatFile = "C:\Users\$env:USERNAME\Downloads\VBCable\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "C:\Users\$env:USERNAME\Downloads\VBCable\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\Users\$env:Username\Downloads\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h'
}

if (!(Get-WmiObject Win32_VideoController | Where-Object name -like "USB Mobile Monitor Virtual Display")) {
    (New-Object System.Net.WebClient).DownloadFile("https://www.amyuni.com/downloads/usbmmidd_v2.zip", "C:\Users\$env:USERNAME\Downloads\usbmmidd_v2.zip")
    Expand-Archive -Path "C:\Users\$env:USERNAME\Downloads\usbmmidd_v2.zip" -DestinationPath "C:\" -Force
    $stream = [IO.File]::OpenWrite('C:\usbmmidd_v2\usbmmidd.bat')
    $stream.SetLength($stream.Length - 7)
    $stream.Close()
    $stream.Dispose()
    "exit" | Add-Content "C:\usbmmidd_v2\usbmmidd.bat"
    Start-Process "C:\usbmmidd_v2\usbmmidd.bat"
    if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
        "@cmd /c deviceinstaller.exe enableidd 1" | Set-Content "C:\usbmmidd_v2\init.bat"
    } else {
        "@cmd /c deviceinstaller64.exe enableidd 1" | Set-Content "C:\usbmmidd_v2\init.bat"
    }
} else {
    Start-Process "C:\usbmmidd_v2\init.bat"
}

if (!(Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ParsecVDD)) {
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe", "C:\Users\$env:USERNAME\Downloads\parsec-vdd.exe")
    Get-PnpDevice | Where-Object {$_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Start-Process "C:\Users\$env:USERNAME\Downloads\parsec-vdd.exe" -ArgumentList "/s" -wait
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
}

if (!(Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Parsec)) {
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "C:\Users\$env:USERNAME\Downloads\parsec-windows.exe")
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Out-File C:\ProgramData\Easy-GPU-P\admim.txt
    Start-Process "C:\Users\$env:USERNAME\Downloads\parsec-windows.exe" -ArgumentList "/silent", "/shared","/team_id=$team_id","/team_computer_key=$key" -wait
    $configfile = Get-Content C:\ProgramData\Parsec\config.txt
    $configfile += "encoder_fps = 144"
    $configfile += "encoder_bitrate = 150"
    $configfile += "encoder_min_qp = 64"
    $configfile += "host_virtual_monitors = 1"
    $configfile += "host_privacy_mode = 1"
    $configfile | Out-File C:\ProgramData\Parsec\config.txt -Encoding ascii
}

if (!(Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Visual C++ 2022%'")) {
    (New-Object System.Net.WebClient).DownloadFile("https://aka.ms/vs/17/release/vc_redist.x86.exe", "C:\Users\$env:USERNAME\Downloads\vc_redist.x86.exe")
    (New-Object System.Net.WebClient).DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", "C:\Users\$env:USERNAME\Downloads\vc_redist.x64.exe")
    Start-Process "C:\Users\$env:USERNAME\Downloads\vc_redist.x86.exe" -ArgumentList "/install" -wait
    Start-Process "C:\Users\$env:USERNAME\Downloads\vc_redist.x64.exe" -ArgumentList "/install" -wait
}