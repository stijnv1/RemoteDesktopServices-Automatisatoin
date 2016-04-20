#
# NewRDSDeployment.ps1
#
param
(
	[string]$RDSWebAccessCBServerName,
	[string]$RDSConnectionBrokerFQDN,
	[string]$RDSSessionHostComputerName,
	[string]$RDSCollectionName,
	[string]$RDSGatewayFQDN,
	[string]$RDSGatewayURL
)

New-RDSessionDeployment -ConnectionBroker $RDSConnectionBrokerFQDN -WebAccessServer $RDSConnectionBrokerFQDN -SessionHost $RDSSessionHostComputerName -verbose
New-RDSessionCollection -CollectionName $RDSCollectionName -SessionHost $RDSSessionHostComputerName -ConnectionBroker $RDSConnectionBrokerFQDN -verbose
Add-RDServer -Server $RDSGatewayFQDN -Role RDS-GATEWAY -ConnectionBroker $RDSConnectionBrokerFQDN -GatewayExternalFqdn $RDSGatewayURL -verbose