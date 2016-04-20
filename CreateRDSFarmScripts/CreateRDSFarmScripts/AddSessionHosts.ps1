#
# AddSessionHosts.ps1
#
param
(
	[string]$RDSSessionHostComputerName,
	[string]$RDConnectionBrokerFQDN,
	[string]$RDSCollectionName
)

Add-RDServer -Server $RDSSessionHostComputerName -ConnectionBroker "$RDConnectionBrokerFQDN" -Role RDS-RD-SERVER -verbose
Add-RDSessionHost -CollectionName $RDSCollectionName -SessionHost $RDSSessionHostComputerName -ConnectionBroker "$RDConnectionBrokerFQDN" -verbose
