#
# DeleteRDSSessionHost.ps1
#
param
(
	[string]$RDSSessionHostComputerName,
	[string]$RDConnectionBrokerFQDN
)

Remove-RDSessionHost -SessionHost $RDSSessionHostComputerName -ConnectionBroker "$RDConnectionBrokerFQDN" -Force
Remove-RDServer -Server $RDSSessionHostComputerName -ConnectionBroker "$RDConnectionBrokerFQDN" -Role RDS-RD-SERVER -Force
