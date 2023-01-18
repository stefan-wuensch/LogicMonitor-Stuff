# LogicMonitor-Stuff

This repo started life 2023-01-18, so bear with me while I gradually add stuff!

## VMware_Guest_Tags_as_Device_Properties

A LM PropertySource and DataSource combo which copies VMware Guest Tags onto the monitored Device.

Normally VM Guest Tags only appear in LogicMonitor on the Instances under one (or maybe more) DataSources on the vCenter server Device (Resource). That's not very useful!

This PropertySource looks for the MAC and IP of a LM Device (Resource) which appears to be a VMware Guest, tries to find it in the collection of all Device-DataSource-Instances on the vCenter server, and if the guest is found as an Instance then all the ILPs are copied as Auto Properties to the Device being monitored.

Example: If you created a Tag in vCenter on your VM Guest which was "environment = Production" then your monitored Device would get a new Property "auto.vcenter.environment = Production"
