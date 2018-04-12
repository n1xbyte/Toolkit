Function Get-Groupname {
$Global:Groupname = Read-Host "Enter group you want to search for users logged in"
if ($Groupname -eq $null){
	Write-Host "Group cannot be blank"
	Get-Groupname}
$GroupCheck = Get-ADGroupMember $Groupname
if ($GroupCheck -eq $null){
	Write-Host "Invalid group"
	Get-Groupname}
}

Get-Groupname

$computers = Get-ADComputer -Filter *
foreach ($comp in $computers)
	{
	$Computer = $comp.Name
  	if (Test-Connection -ErrorAction SilentlyContinue -Count 1 -ComputerName $Computer){
		$Proc = gwmi win32_process -ErrorAction SilentlyContinue -ComputerName $Computer -Filter "Name = 'explorer.exe'"
		ForEach ($P in $Proc) {
	    	$Userz = ($P.GetOwner()).User
	    	for ($i=0; $i -le $Groupname.count; $i++){
	  			if ([string]$Groupname[$i].SamAccountName -eq $Userz){
				write-host "$Userz is logged on $Computer"
		}}}}}
