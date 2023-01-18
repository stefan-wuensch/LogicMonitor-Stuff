// HUIT_VMware_Tags PropertySource Prod 2021-03-10

// by Stefan Wuensch, October 2020
// Updated by Stefan, March 2021 to use VM Status DataSource which also includes PoweredOff VMs
//
//
// --------------------------------------------------------------------------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2023 Stefan Wuensch
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// --------------------------------------------------------------------------------------------------------------------------------------------
//
//
// How does one get VMware Guest Tags to appear on the LM Resource which is the VM Guest?
// This is how! Use the Guest MAC and IP addresses to search for the Instance in vCenter
// on the DataSource "VMware_vCenter_VMStatus" (because that's where Tags appear)
// and then copy all the Auto Properties from that Instance to the monitored Device.
// We will use our own prefix so that name collisions won't be an issue.
// We use the LM API to avoid overloading the vCenter API.
//
// In addition, we will generate at least two new Auto Properties showing
// the start time of the run, and the outcome (good/bad/ugly) at the end.
//      {prefix}.propertysource.start  -->  timestamp of the start
//      {prefix}.propertysource.status -->  message starting with either "OK" or "Failed"
// Note that the "OK" and "Failed" are in globals for easy changing if needed.
// Input and output Property name prefixes are also in globals for easy customization.
//
//
// Required Device Properties for this PropertySource to work:
//   VMware_Tags.lmaccount              - LM portal name (as in lmaccount.logicmonitor.com)
//   VMware_Tags.lmaccess.id            - LM API Token Access ID
//   VMware_Tags.lmaccess.key           - LM API Token Key
//   VMware_Tags.vCenter_Server.name    - system.hostname of the VMware vCenter Server in LM
//   auto.network.mac_address           - VM Guest MAC address, used to find Instance on vCenter Device
//   auto.network.address               - VM Guest IP address, used to find Instance on vCenter Device
//
// Optional Device Properties:
//   collector.proxies.config           - JSON configuration for web proxy if needed for Collector egress
//   (Web proxy password Property)      - Property Name that contains proxy password (if needed) as specified
//                                          in the "proxy.pass.propertyname" JSON element
//
// Shout-out to Stuart Weenig for ideas, for code samples, and for being awesome.
//
// Note: all the significant helper methods are copied from DataSource "LogicMonitor_Portal_Metrics"
// (v1.5 lmLocator 7AGWZ6) for the purposes of re-using code provided by and supported by
// LogicMonitor. This means that some parts of the unique code in this script are not
// as easy to read, nor as compact, as they could be. I thought it better to re-use
// common methods for LM API access rather than to have all original code that might be
// more efficient. -- SW
//

// To configure web proxies for any / each Collector, create a Device Property named
// "collector.proxies.config" with a schema like this example. Note that multiple
// proxy configurations can be created, and are mapped to the Collector ID as applicable.
/*
{
    "proxy_collectors": {
        "7":  "config_A",
        "8":  "config_B",
        "21": "config_A",
        "22": "config_B"
    },
    "config_A": {
        "comment":      "This example proxy is for prod servers",
        "proxy.host":   "10.0.1.10",
        "proxy.port":   "8080",
        "proxy.schema": "https",
        "proxy.user":   "",
        "proxy.pass.propertyname": ""
    },
    "config_B": {
        "comment":      "This is another example",
        "proxy.host":   "my.example.proxy.com",
        "proxy.port":   "8888",
        "proxy.schema": "http",
        "proxy.user":   "john_sample",
        "proxy.pass.propertyname": "collector.proxy.password"
    }
}

*/


import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import groovy.json.JsonSlurper
import groovy.json.JsonOutput ;
import groovy.time.TimeCategory ;
import com.santaba.agent.groovyapi.http.* ;


// Set globals for prefixes and important status flags
autoprop_prefix = "auto.vcenter" ;
my_name         = "VMware_Tags" ;
status_OK_str   = "OK" ;
status_Fail_str = "Failed" ;

// This is in case things like API time-outs show up. Compare this time
// to the "status" property which should be always the last one output.
println "${autoprop_prefix}.propertysource.start=" + time_now() ;


// Build map of customer account credentials (located on LM Portal)
Map credentials = [
    "account": hostProps.get( "${my_name}.lmaccount" ),
    "id"     : hostProps.get( "${my_name}.lmaccess.id" ),
    "key"    : hostProps.get( "${my_name}.lmaccess.key" )
] ;


// Get the Properties we need in order to find vCenter, and this
// VM among all the Guest Instances on vCenter.
String vcenter_name = hostProps.get( "${my_name}.vCenter_Server.name" ) ;
String primary_MAC  = hostProps.get( "auto.network.mac_address" ) ;
String primary_IP   = hostProps.get( "auto.network.address" ) ;

web_proxies = get_proxies() ?: [:] ;   // Making this Map a "global" so it's available to methods without editing input parameters


// Make sure we have what we need, or bail out.
// If we fail, we'll give a helpful status message as a Property.
if ( ! ( credentials.account && credentials.id && credentials.key ) ) {
    println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} on API credentials at ${time_now()} " +
             "Device is not configured with the necessary credentials to proceed with API queries. " +
             "Please ensure that \"${my_name}.lmaccount\", \"${my_name}.lmaccess.id\", and \"${my_name}.lmaccess.key\" are set in the Properties section!"
    ) ;
    return 0 ;
}
if ( ! ( vcenter_name && primary_MAC && primary_IP ) ) {
    println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} on incomplete Device Properties at ${time_now()} " +
             "Could not get the necessary information to proceed with VM Tag matching. " +
             "Please ensure that \"${my_name}.vCenter_Server.name\", \"auto.network.mac_address\", and \"auto.network.address\" are available in the Device Properties section!"
    ) ;
    return 0 ;
}


// IMPORTANT: Filters must be URLencoded, EXCEPT where variables are being used.
// (Generally this just means replacing spaces with '+')
// Note the use of tokens which will be replaced in later stages as those data are gathered.
Map resources = [

    "get_vcenter_ID": [
        "comment": "This gets the Device ID of the VMWare vCenter server whose name provided as a Property.",
        "path": "/device/devices",
        "data": [:],
        "details":  [
            "fields": "id,name,displayName",
            "filter": "displayName:${vcenter_name},systemProperties.name:system.virtualization,systemProperties.value:VMWare+ESX+vcenter"
        ]
    ],

    "get_dataSourceId": [
        "comment": "This uses the vCenter server Device ID from the previous query to get the Device DataSource ID for VMware VM Status.",
        "path": "/device/devices/###vcenter_ID###/devicedatasources",
        "data": [:],
        "details":  [
            "fields": "id,dataSourceId,dataSourceName",
            "filter": "dataSourceName:VMware_vCenter_VMStatus"
        ]
    ],

    "get_instances": [
        "comment": "This uses the vCenter Device ID and the Device DataSource ID from previous queries to get Auto Properties for this VM, based on MAC and IP.",
        "path": "/device/devices/###vcenter_ID###/devicedatasources/###datasource_ID###/instances",
        "data": [],         // Note this is a List not a Map, because we need to handle the possibility of multiple matches.
        "details":  [
            "fields": "name,displayName,autoProperties",
            "filter": "autoProperties.name:auto.hardware.nic0.mac_address,autoProperties.value~${primary_MAC},autoProperties.name:auto.hardware.nic0.ip_addresses,autoProperties.value~${primary_IP}"
//            "filter": "autoProperties.name:auto.hardware.nic0.mac_address,autoProperties.value~00:50:56:8b:5f"      // Test case that deliberately matches 6 VMs
        ]
    ]

] ;


// --------------------------------------------------------------------------------------------------------------------------------------------
// Now in three stanges, we make the API calls.
// (This might be possible to do in a helper method instead, but we need to replace tokens in the 'path' parameters, and re-use all
// the existing methods we have from an existing DataSource without changing them.)

// ---- Stage 1 ------------------------
def this_one = "get_vcenter_ID" ;

Map headers = generate_headers( credentials.id, credentials.key, resources[ this_one ].path ) ;
if ( headers ) {
    Map this_response = get_response( this_one, resources[ this_one ], credentials.account, headers ) ;
    if ( this_response?.success && this_response?.response?.size() != 0 ) { resources[ this_one ][ "data" ] << this_response.response }
    else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} API response for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }
}
else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} generating API auth headers for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }

def vcenter_ID = resources[ this_one ].data?.id?.toString() ;
if ( ! vcenter_ID ) { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} to find vCenter ID in ${this_one} from LM API at ${time_now()}" ) ; return 0 ; }



// ---- Stage 2 ------------------------
headers = [:]   // Reset to empty
this_one = "get_dataSourceId" ;
resources[ this_one ].path = resources[ this_one ].path.replace( "###vcenter_ID###", vcenter_ID ) ;

headers = generate_headers( credentials.id, credentials.key, resources[ this_one ].path ) ;
if ( headers ) {
    Map this_response = get_response( this_one, resources[ this_one ], credentials.account, headers ) ;
    if ( this_response?.success ) { resources[ this_one ][ "data" ] << this_response.response }
    else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} API response for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }
}
else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} generating API auth headers for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }

def datasource_ID = resources[ this_one ].data?.id?.toString() ;
if ( ! datasource_ID ) { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} to find DataSource ID in ${this_one} from LM API at ${time_now()}" ) ; return 0 ; }



// ---- Stage 3 ------------------------
headers = [:]   // Reset to empty
this_one = "get_instances" ;
resources[ this_one ].path = resources[ this_one ].path.replace( "###vcenter_ID###", vcenter_ID ).replace( "###datasource_ID###", datasource_ID ) ;

headers = generate_headers( credentials.id, credentials.key, resources[ this_one ].path ) ;
if ( headers ) {
    Map this_response = get_response( this_one, resources[ this_one ], credentials.account, headers ) ;
    if ( this_response?.success ) { resources[ this_one ][ "data" ] = this_response.response }
    else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} API response for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }
}
else { println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} generating API auth headers for ${this_one} at ${time_now()} (internal error)" ) ; return 0 ; }

// End of the three stage data collection.
// --------------------------------------------------------------------------------------------------------------------------------------------



// We now have everything we can get. Make sure it's only one matching VM!
// If not just one, give a helpful status message and bail out.
def instances_count = resources?.get_instances?.data?.size() ;
def instances_names = resources?.get_instances?.data?.collect{ it.displayName } ;
def instances_names_text = "" ;
if ( instances_count > 1 ) {
    instances_names_text = "with Instance Display Names ${instances_names} " ;
}
if ( instances_count != 1 ) {
    println( "${autoprop_prefix}.propertysource.status=${status_Fail_str} results count at ${time_now()} found ${instances_count} matches " +
             instances_names_text +
             "for MAC \"${primary_MAC}\" and IP \"${primary_IP}\" on vCenter server \"${vcenter_name}\"" 
    ) ;
    return 0 ;
}

// Since we know we have only one match, grab that single list item as a string.
def displayName = instances_names?.getAt( 0 ).toString() ;



// Make sure we're not looking at a VM which is the vCenter server itself. If we are, skip it!
// Because Device Properties get inherited by DataSource Instances, it's really confusing to have
// Properties related to the vCenter VM showing up on Instances which are other Guest VMs!
if ( hostProps.get( "system.deviceId" ) == vcenter_ID ) {
    println( "${autoprop_prefix}.propertysource.status=${status_OK_str} / Skipping VM Tag propagation on this VM Resource " +
             "\"${displayName}\" because this is the vCenter server \"${vcenter_name}\" itself, and the Properties " +
             "would be inherited by the Guest Instances and make things very confusing. / Finished at ${time_now()}"
    ) ;
    return 0 ;
}



// Finally, after all that... Output all the vCenter Instance Auto Properties! Yay!
// Also include the vCenter Instance displayName for cross-reference.
println( "${autoprop_prefix}.displayName=${displayName}" ) ;
// Iterate over the nested items, removing the existing "auto" prefix first. (Our prefix contains "auto.")
resources?.get_instances?.data?.autoProperties?.each() { pair ->
    pair.each() {
        String output_name = it.name.minus( "auto." ) ;
        println( "${autoprop_prefix}.${output_name}=${it.value}" ) ;
    }
}



//println( "${autoprop_prefix}.propertysource.fun=wheeee" ) ;                             // Debug
//println( "${autoprop_prefix}.datasize=${resources?.get_instances?.data?.size()}" ) ;    // Debug
//println( "${autoprop_prefix}.debug=${JsonOutput.toJson( resources ) }" ) ;              // Debug



// All done! Give a wrap-up message with a summary.
def autoProperties_size = resources?.get_instances?.data?.getAt( 0 )?.autoProperties?.size() ;
println( "${autoprop_prefix}.propertysource.status=${status_OK_str} / Finished at ${time_now()} / " +
         "Matched VM Instance \"${displayName}\" on vCenter server \"${vcenter_name}\" " +
         "and replicated ${autoProperties_size} Properties from the vCenter Guest Instance."
) ;
return 0 ;




/* ************************************************************************************************************** */
// Custom helper method(s)


// Generate string of current time
def time_now() {
    return new Date().format( 'yyyy-MM-dd HH:mm:ss' ) ;
}



// Create map for any web proxy needed on this Collector. Returns Map.
def get_proxies() {

	// Get the Web Proxy configuration (if it exists) for use in the HTTP connection.
	// The schema for this Map is illustrated in comments at this top of this script.
	def my_collectorid = hostProps.get( "system.collectorid" ) ?: "0" ;  // We'll be using this for a Map lookup later
	//my_collectorid = "99" // debug

	Map proxies_map = [:] ;     // This will contain all Collector proxy configs, from the Property - if it exists.
	String json_config = hostProps.get( "collector.proxies.config" ) ?: "{}" ;  // parseText() does not like a null!
	try {
		proxies_map = new JsonSlurper().parseText( json_config ) ;
	} catch ( Exception err ) {
		// Just in case someone puts something weird in the Property which makes the Slurper unhappy.
		// Since the proxy config is optional anyway - and we initialized the map - this is belt-and-suspenders safety. :-)
		// Note that we are assuming the "status" Property will be over-written by a later step.
		// This println() is here primarily for really odd edge cases.
		println( "${autoprop_prefix}.propertysource.status=${status_OK_str} but there was a problem parsing JSON from Property \"collector.proxies.config\" ${err?.message}" )
	}

	// If we did get a proxy config for this Collector, use it!
	// Note we're doing everything null-safe with getAt() because it's user input from Properties!
	// We don't want to assume the Map schema is what it should be.
	// System Property Reference: https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/prest/groovy_sample_pbcsrestclient.groovy.html
	// and https://generacodice.com/en/articolo/37540/How-can-I-enumerate-all-%2A.exes-and-the-details-about-each
	// and https://www.logicmonitor.com/support/terminology-syntax/scripting-support/access-a-website-from-groovy
	
	// Also note: System.setProperty() makes a *persistent* change to the JVM (as of 2020-10-27) which is sub-optimal. Those VM-wide settings lines of code are
	// kept here but disabled, in case it's desired behavior. Instead this method returns a Map to be used in setHTTPProxy() on a httpClient object.

	if ( proxies_map?.getAt( "proxy_collectors" )?.containsKey( my_collectorid ) ) {                    // Is this Collector ID a key in the map?
		String config_name = proxies_map?.getAt( "proxy_collectors" )?.getAt( my_collectorid ) ;        // This is for making the notation a little shorter.
		if ( proxies_map?.containsKey( config_name ) ) {                                                // Is the config by this name in the map?
			String my_schema = proxies_map?.getAt( config_name )?.getAt( "proxy.schema" ) ?: "https" ;  // Use https if not otherwise specified

			// Take care of Host / Port first, and use a null if it's not found.
			// Note we are NOT doing any validation of the values. If someone got the JSON schema correct
			// to this level, we'll assume they knew what they were doing enough to give proper values.
            /* See note above about System.setProperty()
			System.setProperty( "${my_schema}.proxyHost", proxies_map?.getAt( config_name )?.getAt( "proxy.host" ) ?: "" ) ;
			System.setProperty( "${my_schema}.proxyPort", proxies_map?.getAt( config_name )?.getAt( "proxy.port" )?.toInteger() ?: "" ) ;
			*/
			Map return_map = [
			    "schema": my_schema,
			    "host": proxies_map?.getAt( config_name )?.getAt( "proxy.host" ) ?: "",
			    "port": proxies_map?.getAt( config_name )?.getAt( "proxy.port" )?.toInteger() ?: ""
	        ] ;
		
			// Proxy password is in a separate Device Property, which keeps it safe.
			String password_prop_name = proxies_map?.getAt( config_name )?.getAt( "proxy.pass.propertyname" ) ?: "" ; // Get the name of that Property
			if ( password_prop_name ) {
                /* See note above about System.setProperty()
			    System.setProperty( "${my_schema}.proxyUser", proxies_map?.getAt( config_name )?.getAt( "proxy.user" ) ?: "" ) ;
				System.setProperty( "${my_schema}.proxyPassword", hostProps.get( password_prop_name ) ?: "" ) ;    // hostProps.get() returns null if not found, but we want empty string
				*/
			    return_map[ "user" ] = proxies_map?.getAt( config_name )?.getAt( "proxy.user" ) ?: "" ;
				return_map[ "pass" ] = hostProps.get( password_prop_name ) ?: "" ;
			}

            return return_map ;
		}
	}

}




/* ************************************************************************************************************** */
// Helper methods from here to end, copied from DataSource LogicMonitor_Portal_Metrics v1.5 lmLocator 7AGWZ6
// Note that minor changes have been made to the error output, so that it conforms to PropertySource format
// which requires "name=value" for all lines.

def generate_headers(id, key, path) {
    try {
        // Create encryption signature for authorization request
        Long epoch_time = System.currentTimeMillis()    // Get current system time (epoch time)
        Mac hmac = Mac.getInstance("HmacSHA256")
        hmac.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"))

        signature = hmac.doFinal("GET${epoch_time}${path}".getBytes()).encodeHex().toString().bytes.encodeBase64()
        // return headers to main function
        return ["Authorization": "LMv1 $id:$signature:$epoch_time", "Content-Type": "application/json"]
    } catch (Exception err) {
        // If error occurred, print the error message
        // println("ERROR: Unable to establish encryption for $path. Attempting next resource...\n${err.message}")      // Original line from LM DataSource
        println("${autoprop_prefix}.propertysource.status=${status_Fail_str} ERROR: Unable to establish encryption for $path. Attempting next resource... ${err.message}") // Output fixed for PropertySource
    }
}

def get_response(resource, parameters, account, headers) {
    try {
        boolean proceed = true  // Boolean used to determine if additional pagination is required
        // Map to store query results for each endpoint.  Contains a list to store actual returned values and a boolean to determine if successful
        Map results = ["response": [],
                       "success" : true]
        add_query_parameters(resource, parameters)
        // Add initial offset and size values to appropriate categories (skips metrics category since it's stagnate)
        while (proceed) {
            // Used for paginating through all availabe results.  Grabs 1000 at a time and moves offset if another query is required.
            Map query = query_resource(account, parameters, headers)
            // Query each API endpoint for a response (Should receive as Map)
            // If the response was successful (including status and error messages), proceed to printing results
            if (query && query?.data && query?.status == 200 && query?.errmsg?.toUpperCase() == "OK") {
                if (resource != "metrics") {
                    results.response.addAll(query.data.items)   // Add all the data items found to our results map data list
                    if (query?.data?.items?.size() < parameters.details.size) {
                        // If we received less than 1000 results
                        proceed = false     // There is no need to execute another API query with a shifted offset
                    } else {        // Otherwise
                        parameters.details.offset += parameters.details.size
                        // Shift the offset to start 1000 numbers from current position
                    }
                } else {
                    results.response = query.data   // Add all the data items found to our results map data list
                    proceed = false     // We've successfully queried all values.  End while loop
                }
            } else {
                // If response was not successful, print eror message for each category that failed and continue to next endpoint
                // If response error and status can be determined, print them.  Otherwise, use UNKNOWN
                // println("ERROR: Failed to query $resource API Endpoint...\n" +   // Original line from LM DataSource
                println("${autoprop_prefix}.propertysource.status=${status_Fail_str} ERROR: Failed to query $resource API Endpoint... " +  // Output fixed for PropertySource
                        "${query?.errmsg?.toUpperCase() ?: 'UNKNOWN'} (STATUS: ${query?.status ?: 'UNKNOWN'})")
                results.success = false     // Set success value to false since we failed our API query
                proceed = false   // End while loop because of failure and proceed to next endpoint
            }
        }
        return results  // Return results to main function
    } catch (Exception err) {
        // println("ERROR: Script failed while attempting to query $resource API endpoint...\n${err?.message}") // Original line from LM DataSource
        println("${autoprop_prefix}.propertysource.status=${status_Fail_str} ERROR: Script failed while attempting to query $resource API endpoint... ${err?.message}") // Output fixed for PropertySource
    }
}

def add_query_parameters(category, parameters) {
    // Add size and offset field to map (only if collectors or admins category)
    if (category != "metrics") {
        Map query_details = ["size"  : 1000,
                             "offset": 0]
        // If there's already a details key in the details map
        if (parameters.details) {
            parameters.details << query_details
            // Append the query details information to the pre-existing details map
        } else {    // Otherwise, create a details key and assign it the query details map as a value
            parameters.put("details", query_details)
        }
    }
}

def query_resource(account, details, headers) {
    try {
        // Configure request url from account, path, and authorization headers
        String url = "https://${account}.logicmonitor.com/santaba/rest${details.path}?${pack_parameters(details.details)}"
        // Return query response, converted from JSON to usable map
        // Next line is from original DataSource, but doesn't work with web proxies.
        // return new JsonSlurper().parseText(url.toURL().getText(useCaches: true, allowUserInteraction: false, requestProperties: headers))

        // Next lines added by Stefan Wuensch, October 2020, to be able to use web proxies
        // println( "${autoprop_prefix}.debug=${JsonOutput.toJson( web_proxies ) }" ) ;    // Debug
        def client = HTTP.open( "${account}.logicmonitor.com", 443, true ) ;            // Specify SSL (true) for just-in-case belt-and-suspenders coverage
        if ( web_proxies && web_proxies?.host && web_proxies?.port ) {
            client.setHTTPProxy( web_proxies?.host, web_proxies?.port, web_proxies?.user, web_proxies?.pass ) ;
        }
        def response = client.get( url, headers ) ;         // We don't need this object; it's just to make the get() happen.
        def response_body = client.getResponseBody() ;
        return new JsonSlurper().parseText( response_body ) ;

    } catch (Exception err) {
        // If error occurred, print the error message
        // println("ERROR: Unable to query ${details.path} for details.\n${err.message}")  // Original line from LM DataSource
        println("${autoprop_prefix}.propertysource.status=${status_Fail_str} ERROR: Unable to query ${details.path} for details. ${err.message}")      // Output fixed for PropertySource
    }
}

def pack_parameters(query_details) {
    // If additional query details are located in map, include them in url string
    List pairs = []
    query_details?.each { k, v ->
        pairs.add("${k}=${v}")
    }
    return pairs.join("&")
}

/* ************************************************************************************************************** */
