/*
Monitor the Device Property "auto.vmware.ad.vm.mode" and Alert:
 Critical (metric 1) if Property value is "light";
 Error if Property is not set, or if there's a problem in the code.
 Metric value 0 (zero) is normal / OK meaning Property value is "full".
*/


String mode = taskProps.get( "auto.vmware.ad.vm.mode" ) ?: "unknown"

switch ( mode ) {

    case "full": 
        return( 0 )
        break

    case "light": 
        return( 1 )
        break

    case "unknown": 
        return( 2 )
        break
    
}

return( 2 ) // In case something goes wrong, instead of using a "default" case.
