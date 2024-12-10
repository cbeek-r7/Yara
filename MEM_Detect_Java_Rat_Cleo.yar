rule MEM_Detect_Java_RAT_Cleo {
    meta:
        description = "Detects Java classes observed in the abuse of the Cleo File transfer software"
        author = "Christiaan Beek"
        reference = "https://www.rapid7.com/blog/post/2024/12/10/etr-widespread-exploitation-of-cleo-file-transfer-software-cve-2024-50623/"
    
    strings:
        $class_srvslot = "SrvSlot" ascii wide
        $class_dwn = "Dwn" ascii wide
        $class_proc = "Proc" ascii wide
        $class_scslot = "ScSlot" ascii wide
        $debug_cmd1 = "#dbg#" ascii wide
        $debug_cmd2 = "#lsz#" ascii wide
        $key_crkey = { 1f ce 49 b1 23 71 73 3c 2e 8f f6 6f 3e f8 54 26 21 98 d5 61 a2 b1 4e b6 65 8d 6b 64 00 ea 1d 3d }

    condition:
        all of ($class_*) or $key_crkey or any of ($debug_cmd*)
}
