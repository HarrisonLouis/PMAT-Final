rule SikoMode {
    
    meta: 
        last_updated = "2023-07-30"
        author = "Harrison Louis"
        description = "This rule can be used to identify the SikoMode malware"

    strings:
        $string1 = "SikoMode"
        $string2 = "nim"
        $string3 = "HTTP"
        $string4 = "C:\\Users\\Public\\passwrd.txt"
        $string5 = "cdn.altimiter.local"
        $PE_magic_byte = "MZ"

    condition:
        $PE_magic_byte at 0 and
        all of ($string*)
}
