#
# AddRDSWebAccessConnectionBroker.ps1
#
param
(
	[string]$RDSWebAccessCBComputerName,
	[string]$RDSConnectionBrokerFQDN
)

Add-RDServer -Server $RDSWebAccessCBComputerName -Role RDS-WEB-ACCESS -ConnectionBroker $RDSConnectionBrokerFQDN -verbose
