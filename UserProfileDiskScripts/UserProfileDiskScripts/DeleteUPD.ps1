#
# DeleteUPD.ps1
#
#
#
param
(
	[Parameter(Mandatory=$true)]
	[string]$ADUserUPN,

	[Parameter(Mandatory=$false)]
	[string]$ConfigParameterCSV = "D:\Sources\Powershell Scripts\UPDScriptConfigParameters.csv",

	[Parameter(Mandatory=$true)]
	[string]$LogDirPath,

	[Parameter(Mandatory=$false)]
	[switch]$OnlyDeleteBakRegistryProfileKeys
)

Function WriteToLog
{
	param
	(
		[string]$LogPath,
		[string]$TextValue,
		[bool]$WriteError
	)

	Try
	{
		#create log file name
		$thisDate = (Get-Date -DisplayHint Date).ToLongDateString()
		$LogFileName = "DeleteUserRDSUPD_$thisDate.log"

		#write content to log file
		if ($WriteError)
		{
			Add-Content -Value "[ERROR $(Get-Date -DisplayHint Time)] $TextValue" -Path "$LogPath\$LogFileName"
		}
		else
		{
			Add-Content -Value "[INFO $(Get-Date -DisplayHint Time)] $TextValue" -Path "$LogPath\$LogFileName"
		}
	}
	Catch
	{
		$ErrorMessage = $_.Exception.Message
		Write-Host "Error occured in WriteToLog function: $ErrorMessage" -ForegroundColor Red
	}

}

Try
{
	$ConfigParamters = Import-Csv -Path $ConfigParameterCSV -Delimiter ";"

	#region compose selection menu to select correct collection
	#ask for the correct collection. Each RDS collection has its own dedicated RDS share path to store UPD disks
    #create choice menu to select correct RDS collection
    [int]$selectedMenuItem = 0
	[int]$RDSCollectionCounter = 1
	$SelectionMenu = @{}

	Write-Host "`n`nSelect the correct RDS Collection in the menu below:" -ForegroundColor Green
	foreach ($RDSCollectionLine in $ConfigParamters)
	{
		Write-Host "$RDSCollectionCounter. $($RDSCollectionLine.RDSCollectionName)"
		$SelectionMenu.Add($RDSCollectionCounter,$RDSCollectionLine)
		$RDSCollectionCounter++
	}

    Write-Host "--------------------------------------------------------------------------------------------`n"
    while ($selectedMenuItem -lt 1 -or $selectedMenuItem -gt ($RDSCollectionCounter-1))
    {
        $selectedMenuItem = Read-Host "RDS Collection Name"
    }

    $RDSCollection = $SelectionMenu.Item($selectedMenuItem)
	#endregion

	#region get user SID. SID is needed to delete correct registry keys on the RDS session hosts of the selected collection
	if ($aduser = Get-ADUser -Filter {UserPrincipalName -eq $ADUserUPN} -erroraction SilentlyContinue)
	{
		WriteToLog -LogPath $LogDirPath -TextValue "User $ADUserUPN is found in Active Directory. Following SID is being used: $($aduser.SID)"
		Write-Host "`nSuccessfully found user $ADUserUPN.`nSID = $($aduser.SID) ..." -ForegroundColor Yellow
	}
	else
	{
		Write-Host "`nThe specified user cannot be found in Active Directory" -ForegroundColor Red
		WriteToLog -LogPath $LogDirPath -TextValue "The specified user $ADUserUPN cannot be found in Active Directory" -WriteError $true
	}
	#endregion

	#region delete registry keys on RDS servers of selected RDS collection
	if ($aduser)
	{
		$RDSSessionHosts = Get-RDSessionCollection $RDSCollection.RDSCollectionName -ConnectionBroker $RDSCollection.ConnectionBroker | Get-RDSessionHost -ConnectionBroker $RDSCollection.ConnectionBroker

		$ScriptBlockRemoteRegistry = {
			param
			(
				[string]$userSID
			)

			$RegKeys = @()
			$ProfileListKey = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSID*.bak" | Remove-Item -Recurse -WhatIf
			$ProfileGUIDKey = (Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid\*" | Get-ItemProperty | ? SidString -eq $userSID).PSPath
			$ProfileGUIDKey | Remove-Item -Recurse -WhatIf

			Write-Host "`nStart deleting following registry keys:" -ForegroundColor yellow
			Write-Host $ProfileListKey -ForegroundColor Yellow
			Write-Host $ProfileGUIDKey -ForegroundColor Yellow

			$RegKeys += $ProfileListKey
			$RegKeys += $ProfileGUIDKey

			Return $RegKeys
		}

		Foreach ($RDSSessionHost in $RDSSessionHosts)
		{
			$RegKeysFound = Invoke-Command -ComputerName $RDSSessionHost.SessionHost -ScriptBlock $ScriptBlockRemoteRegistry -ArgumentList $aduser.SID, $LogDirPath

			foreach ($regKey in $RegKeysFound)
			{
				WriteToLog -LogPath $LogDirPath -TextValue "Following registry key will be deleted: $regKey" -WriteError $false
			}
		}
	}
    #endregion

	#region Optionally, delete the User Profile Disk
	if (!$OnlyDeleteBakRegistryProfileKeys)
    {
        #delete corresponding user profile disk
		Write-Host "Following UPD will be deleted: $($RDSCollection.CollectionUPDSharePath)\UVHD-$($aduser.SID).vhdx"

		#discover whether UPDs are still mounted on RDS session hosts of the selected collection
		#if still mounted, but no user profile directory is associated as mount point, these disks can be dismounted
		#a search is done with the labe user disk and the name of the returned wmi query not equal to a user path
        
        $DiskIDsToBeRemoved = @()

		Foreach ($RDSSessionHost in $RDSSessionHosts)
		{
			$WMIGetVolumes = Get-WmiObject Win32_Volume -ComputerName $RDSSessionHost.SessionHost | ? Label -eq "User Disk" | select-object Name, Label

			foreach ($volume in $WMIGetVolumes)
			{
				if ($volume.Label -eq "User Disk")
				{
					if ($volume.Name -like "\\?\Volume{*")
					{
						#get disk number associated with this volume
						$diskInfo = get-volume -CimSession $RDSSessionHost.SessionHost | ? Path -eq $($volume.Name) | Get-Partition | Get-Disk | Select-Object Number
						$DiskObject = New-Object PSObject
						$DiskObject | Add-Member -MemberType NoteProperty -Name "RDSSessionhostName" -Value $RDSSessionHost.SessionHost
						$DiskObject | Add-Member -MemberType NoteProperty -Name "DiskID" -Value $diskInfo.Number
						$DiskIDsToBeRemoved += $DiskObject

						Write-Host "Dismount volume with name $($volume.Name) on RDS Session Host $($RDSSessionHost.SessionHost)" -ForegroundColor Yellow
						WriteToLog -LogPath $LogDirPath -TextValue "Dismounting volume $($volume.Name) with Disk ID $($DiskObject.DiskID) on RDS Session Host $($RDSSessionHost.SessionHost)"
						$VolumeToBeDismounted = Get-WmiObject Win32_Volume -ComputerName $RDSSessionHost.SessionHost | ? Name -eq $volume.Name
						$VolumeToBeDismounted.Dismount($true,$true)
					}
				}
			}
		}

		Write-Host "Following disks can be detached on the RDS session hosts of collection $($RDSCollection.RDSCollectionName):"
		$DiskIDsToBeRemoved

		#delete the VHDX on the file server
		Get-Item -Path "$($RDSCollection.CollectionUPDSharePath)\UVHD-$($aduser.SID).vhdx"
    }

	#endregion
}

Catch
{
	$ErrorMessage = $_.Exception.Message
	WriteToLog -LogPath $LogDirPath -TextValue "Error occured: $ErrorMessage" -WriteError $true
	Write-Host "Error occured: $ErrorMessage"
}