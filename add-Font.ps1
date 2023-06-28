#Script to Install Fonts

#Check for font 



#$fonts = (New-Object -ComObject Shell.Application).Namespace(0x14)
$DC = "ctsdc1"
$Path = Test-Path \\$DC\netlogon\font
if($Path -eq $true)
{
Write-EventLog -Source Application -LogName Application -EventId 301 -EntryType Information -Message "The Network Path is True" 
$fontFolder = "\\$DC\NETLOGON\Font"
$fontItem = Get-Item -Path $fontFolder
$fontList = Get-ChildItem -Path "$fontItem\*" -Include ('*.fon','*.otf','*.ttc','*.ttf')
$RegPath =(Test-Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Fonts')
$objFont = New-Object System.Drawing.Text.PrivateFontCollection

}else{
        Write-EventLog -Source Application -LogName Application -EventId 309 -EntryType Error -Message "Path not reachable"
            }
        
foreach ($font in $fontList) 
 {
    #Font Object Construction
   $objFont.AddFontFile($font.FullName)
   $objTitle = $objFont.Families[-1].Name 
   $fontName = $font.Name
   $objExtension = switch ($font.Extension)
    {
     .TTF {"(TrueType)"}
     .OTF {"(OpenType)"}
           Default {
            Write-EventLog -Source Application -LogName Application -EventId 305 -EntryType Information -Message "Font Extension not Found"
            }
         }
     $FontTitle = $objTitle + " " + $objExtension

     #Conditionals To determine necessary functions of installation. 

     if (-not(Test-Path -Path "C:\Windows\fonts\$fontName" )) 
     {
        Write-EventLog -Source Application -LogName Application -EventId 302 -EntryType Information -Message "Font not Found, Installing font."
        echo $fontName
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v $FontTitle /t REG_SZ /d DWBAR39.TTF /f
        cp $font C:\Windows\Fonts 
        
        
                }if(Test-Path -Path "C:\Windows\fonts\$fontName")
                    {
                    Write-EventLog -Source Application -LogName Application -EventId 303 -EntryType Information -Message "Font successfully Installed in C:\windows\fonts"
                        }else{
                            Write-EventLog -Source Application -LogName Application -EventID 310 -EntryType Information -Message "Font failed to install in C:\windows\fonts"
                                }
                            
  }
    
   
 


 