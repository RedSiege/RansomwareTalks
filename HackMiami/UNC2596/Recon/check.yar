rule ICMPCHECK_PoC {
    meta:
        last_updated = "2023-2-2"
        author = "Grimmie"
        description = "YARA Rule for ICMP discover tool (check.exe) as present at HackMiami by FortyNorthSec"
    
    strings:
        $namespace1 = "System.Collection" nocase ascii
        $namespace2 = "System.Runtime" nocase ascii
        $namespace3 = "System.Refelction" nocase ascii
        $namespace4 = "System.Diagnostics" nocase ascii
        $namespace5 = "System.Net" nocase ascii
        $namespace6 = "System.IO" nocase ascii

        $api1 = "IcmpCreateFile" nocase ascii
        $api2 = "IcmpCloseHandle" nocase ascii
        $api3 = "IcmpSendEcho" nocase ascii

        $dll1 = "icmp" nocase ascii

        $misc1 = "ICMP_OPTIONS" nocase ascii
        $misc2 = "ICMP_ECHO_REQUEST" nocase ascii
        $misc3 = "OptionSize" nocase ascii
        $misc4 = "replySize" nocase ascii
        $misc5 = "requestSize" nocase ascii
        $misc6 = "RoundTripTime" nocase ascii
        $misc7 = "GetAddressBytes" nocase ascii


    condition:
        all of $namespace* and
        all of $api* and 
        all of $dll* and 
        all of $misc*

}
