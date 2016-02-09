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
	[switch]$OnlyDeleteBakRegistryProfileKeys,

	[Parameter(Mandatory=$true)]
	[string]$RDSConnectionBrokerFQDN
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
	#$ConfigParamters = Import-Csv -Path $ConfigParameterCSV -Delimiter ";"

	#region compose selection menu to select correct collection
	#ask for the correct collection. Each RDS collection has its own dedicated RDS share path to store UPD disks
    #create choice menu to select correct RDS collection
    [int]$selectedMenuItem = 0
	[int]$RDSCollectionCounter = 1
	$SelectionMenu = @{}

	Write-Host "`n`nSelect the correct RDS Collection in the menu below:" -ForegroundColor Green
	#foreach ($RDSCollectionLine in $ConfigParamters)
	#{
	#	Write-Host "$RDSCollectionCounter. $($RDSCollectionLine.RDSCollectionName)"
	#	$SelectionMenu.Add($RDSCollectionCounter,$RDSCollectionLine)
	#	$RDSCollectionCounter++
	#}
	$RDSCollections = Get-RDSessionCollection -ConnectionBroker $RDSConnectionBrokerFQDN

	foreach ($RDSCol in $RDSCollections)
	{
		Write-Host "$RDSCollectionCounter. $($RDSCol.CollectionName)"
		$SelectionMenu.Add($RDSCollectionCounter,$RDSCol)
		$RDSCollectionCounter++
	}

    Write-Host "--------------------------------------------------------------------------------------------`n"

    while ($selectedMenuItem -lt 1 -or $selectedMenuItem -gt ($RDSCollectionCounter-1))
    {
        $selectedMenuItem = Read-Host "RDS Collection Name (give sequence number of menu item)"
    }

    $RDSCollection = $SelectionMenu.Item($selectedMenuItem)
	$RDSCollectionUPDShareRootPath = ($RDSCollection | Get-RDSessionCollectionConfiguration -ConnectionBroker $RDSConnectionBrokerFQDN -UserProfileDisk).DiskPath
	#endregion

	#region ask local admin credentials for RDS session hosts
	Write-Host "--------------------------------------------------------------------------------------------`n"
	$RDSSessionhostUsername = Read-Host "`nGive the username of a local administrator account of the RDS session hosts"
	$RDSSessionhostPassword = Read-Host "Give the password of the given username" -AsSecureString
	Write-Host "--------------------------------------------------------------------------------------------`n"

	$RDSSessionhostCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $RDSSessionhostUsername, $RDSSessionhostPassword
	#endregion

	#region get user SID. SID is needed to delete correct registry keys on the RDS session hosts of the selected collection
	if ($aduser = Get-ADUser -Filter {UserPrincipalName -eq $ADUserUPN} -erroraction SilentlyContinue)
	{
		WriteToLog -LogPath $LogDirPath -TextValue "User $ADUserUPN is found in Active Directory. Following SID is being used: $($aduser.SID)"
		Write-Verbose "`nSuccessfully found user $ADUserUPN.`nSID = $($aduser.SID) ..."
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
		$RDSSessionHosts = $RDSCollection | Get-RDSessionHost -ConnectionBroker $RDSConnectionBrokerFQDN

		$ScriptBlockRemoteRegistry = {
			param
			(
				[string]$userSID,
				[string]$RDSSessionHost
			)

			$RegKeys = @()
			$ProfileListKey = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSID*" -ErrorAction SilentlyContinue
			$ProfileGUIDKeyRoot = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid\*"
			$ProfileGUIDKey = $ProfileGUIDKeyRoot | Get-ItemProperty -ErrorAction SilentlyContinue | ? SidString -eq $userSID.PSPath
			

			Write-Verbose "`nStart deleting following registry keys:"
			Write-Verbose "Deleting key $ProfileListKey ..."

			if ($ProfileListKey)
			{
				$ProfileListKey | Remove-Item -Recurse
				if (!(Test-Path -Path $ProfileListKey -ErrorAction SilentlyContinue))
				{
					Write-Verbose "Delete action of registry key $ProfileListKey was successful"
				}
				else
				{
					Write-Verbose "Delete action of registry key $ProfileListKey failed"
				}
			}
			else
			{
				Write-Host "No ProfileListKey was found for the specified user account on RDS session host $RDSSessionHost" -ForegroundColor Green
			}

			Write-Verbose "Deleting key $ProfileGUIDKey ..."

			if ($ProfileGUIDKey)
			{
				$ProfileGUIDKey | Remove-Item -Recurse
				if (!(Test-Path -Path $ProfileGUIDKey -ErrorAction SilentlyContinue))
				{
					Write-Verbose "Delete action of registry key $ProfileGUIDKey was successful"
				}
				else
				{
					Write-Verbose "Delete action of registry key $ProfileGUIDKey failed"
				}
			}
			else
			{
				Write-Host "No ProfileGUIDKey was found for the specified user account on RDS session host $RDSSessionHost" -ForegroundColor Green
			}

			$RegKeys += $ProfileListKey
			$RegKeys += $ProfileGUIDKey

			Return $RegKeys
		}

		Foreach ($RDSSessionHost in $RDSSessionHosts)
		{
			$RegKeysFound = Invoke-Command -ComputerName $RDSSessionHost.SessionHost -ScriptBlock $ScriptBlockRemoteRegistry -ArgumentList $aduser.SID,$RDSSessionHost.Sessionhost -Verbose

			foreach ($regKey in $RegKeysFound)
			{
				if ($regKey -ne $null)
				{
					WriteToLog -LogPath $LogDirPath -TextValue "Following registry key was deleted on RDS session host $($RDSSessionHost.SessionHost): $regKey" -WriteError $false
				}
				else
				{
					WriteToLog -LogPath $LogDirPath -TextValue "Registry key was null" -WriteError $true
				}
			}
		}
	}
    #endregion

	#region Optionally, delete the User Profile Disk
	if (!$OnlyDeleteBakRegistryProfileKeys)
    {
        #delete corresponding user profile disk
		Write-Host "Following UPD will be deleted: $RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx" -ForegroundColor Green
		$diskPath = "$RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx"

		#discover whether UPDs are still mounted on RDS session hosts of the selected collection
		#if still mounted, but no user profile directory is associated as mount point, these disks can be dismounted
		#a search is done with the labe user disk and the name of the returned wmi query not equal to a user path
        
        $DiskIDsToBeRemoved = @()

		Foreach ($RDSSessionHost in $RDSSessionHosts)
		{
			Try
			{
				$DismountDiskScriptBlock = {
					param
					(
						$RDSUPDSharePath
					)

					$outputCommand = Dismount-DiskImage -ImagePath $RDSUPDSharePath -PassThru
					return $outputCommand
				}

				$outputDismount = Invoke-Command -ComputerName $RDSSessionHost.Sessionhost -ScriptBlock $DismountDiskScriptBlock -ArgumentList $diskPath -Authentication Credssp -Credential $RDSSessionhostCred -ErrorAction Stop
				if ($outputDismount)
				{
					Write-Verbose "Dismount on RDS session host $($RDSSessionHost.Sessionhost) was successful"
					WriteToLog -LogPath $LogDirPath -TextValue "UPD is successfully detached from RDS session host $($RDSSessionHost.Sessionhost)" -WriteError $false
				}
				else
				{
					Write-Verbose "UPD detach action failed from RDS session host $($RDSSessionHost.Sessionhost). It is possible that the UPD disk was not attached to this RDS session host"
					WriteToLog -LogPath $LogDirPath -TextValue "UPD detach action failed from RDS session host $($RDSSessionHost.Sessionhost). It is possible that the UPD disk was not attached to this RDS session host" -WriteError $true
				}
			}
			Catch
			{
				$ErrorMessage = $_.Exception.Message
				WriteToLog -LogPath $LogDirPath -TextValue "Error occured while detaching UPD on session host $($RDSSessionHost.Sessionhost): $ErrorMessage" -WriteError $true
				Write-Verbose "Error occured while detaching UPD on session host $($RDSSessionHost.Sessionhost): $ErrorMessage"
			}
		}
		#delete the VHDX on the file server
		Write-Verbose "Deleting the VHDX file of the UPD ..."
		
		if ($diskItem = Get-Item -Path "$RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx" -ErrorAction SilentlyContinue)
		{
			Remove-Item $diskItem -ErrorAction SilentlyContinue
			if(!(Test-Path $diskItem))
			{
				WriteToLog -LogPath $LogDirPath -TextValue "VHDX $RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx successfully deleted." -WriteError $false
				Write-Host "Successfully deleted VHDX" -ForegroundColor Green
			}
			else
			{
				WriteToLog -LogPath $LogDirPath -TextValue "Delete of VHDX $RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx failed." -WriteError $true
				Write-Host "Delete of VHDX failed." -ForegroundColor Red
			}
		}
		else
		{
			WriteToLog -LogPath $LogDirPath -TextValue "User profile disk $RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx was not found" -WriteError $true
			Write-Host "User profile disk $RDSCollectionUPDShareRootPath\UVHD-$($aduser.SID).vhdx was not found" -ForegroundColor Red
		}
    }

	#endregion
}

Catch
{
	$ErrorMessage = $_.Exception.Message
	WriteToLog -LogPath $LogDirPath -TextValue "Error occured: $ErrorMessage" -WriteError $true
	Write-Host "Error occured: $ErrorMessage" -ForegroundColor Red
}