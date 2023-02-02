
rule PersistAssist_Yara {
    meta:
        last_updated = "2023-2-2"
        author = "Grimmie"
        description = "YARA Rule for PHOTOLOADER PoC as presented at HackMiami by FortyNorthSec"

    strings:
        // namespaces used
        $namespace1 = "System.Runtime" nocase ascii 
        $namespace2 = "System.Diagnostics" nocase ascii
        $namespace3 = "System.Net" nocase ascii 
        $namespace4 = "System.Text" nocase ascii

        // api used
        $api1 = "VirtualAlloc" nocase ascii 

        // dlls imported
        $dll1 = "Kernel32" nocase ascii

        //misc strings
        $misc1 = "Convert" nocase ascii
        $misc2 = "FromBase64" nocase ascii
        $misc3 = "HttpRequestHeader" nocase ascii
        $misc4 = "GetBytes" nocase ascii
        $misc5 = "DownloadString" nocase ascii
        $misc6 = "get_SecurityProtocol" nocase ascii

    condition:
        all of $api* and
        all of $dll* and
        all of $namespace* and
        all of misc*
}
