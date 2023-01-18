by Stefan Wuensch, 2022-05-02. 

This DataSource verifies that LogicMonitor is configured properly so that the PropertySource "HUIT_VMware_Tags" will work. 

The Instance Level Properties on VM Guests (which come from VMware Guest Tags in vCenter) will not be created unless "auto.vmware.ad.vm.mode" is "full" on the vCenter server Resource in LM.

Watch the Device Property "auto.vmware.ad.vm.mode" which should always be value "full" for VM Guest Tags to be assigned as Instance Level Properties. 
Alert to Critical if the value is not "full".

