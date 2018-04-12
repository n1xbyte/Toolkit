Function Get-Username {
$Global:Username = Read-Host "Enter username you want to search for"
if ($Username -eq $null){
	Write-Host "Username cannot be blank"
	Get-Username}
$UserCheck = Get-ADUser $Username
if ($UserCheck -eq $null){
	Write-Host "Invalid username"
	Get-Username}
}

Get-Username

$computers = Get-ADComputer -Filter *
foreach ($comp in $computers)
	{
	$Computer = $comp.Name
  	if (Test-Connection -ErrorAction SilentlyContinue -Count 1 -ComputerName $Computer){
		$Proc = gwmi win32_process -ErrorAction SilentlyContinue -ComputerName $Computer -Filter "Name = 'explorer.exe'"
		ForEach ($P in $Proc) {
	    	$Userz = ($P.GetOwner()).User
	  		if ($Userz -eq $Username){
			write-host "$Username is logged on $Computer"
		}}}}
