rule MAL_RANSOM_ELF_ESXiArgs {
   meta:
      description = "Detects the ESXiArgs ransomware targeting viulnerable ESXi servers"
      author = "Christiaan _ Beek @ rapid7 dot com "
      date = "2023-02-09" // including latest change to prevent recovery
   
   strings:

      $code1= { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 83 }
      $code2 = { 5? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 8B ?? ?? ?? ?? ?? 83 ?? ?? 0F 87 }
      $code3 = { 5? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 8B ?? ?? ?? ?? ?? 83 ?? ?? 0F 87 }
      $code4 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0F 82 }
      $code5 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d}
   
   condition:
      uint16(0) == 0x457f and
      filesize < 300KB and 
         all of ($code*)   
}