rule Detect_Localtonet_Exe {
    meta:
        description = "Detects Localtonet Presence On Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["CompanyName"] == "localtonet") or
            (pe.version_info["FileDescription"] == "localtonet") or
            (pe.version_info["InternalName"] == "localtonet.dll") or
            (pe.version_info["OriginalFilename"] == "localtonet.dll") or
            (pe.version_info["ProductName"] == "localtonet")
        )
    )
}

rule Detect_NSSM_Exe {
    meta:
        description = "Detects NSSM Presence On Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["Comments"] == "http://nssm.cc") or
            (pe.version_info["FileDescription"] == "The non-sucking service manager") or
            (pe.version_info["ProductName"] == "NSSM 32-bit") or
            (pe.version_info["ProductName"] == "NSSM 64-bit")
        )
    )
}

rule Detect_XenArmor_Exe {
    meta:
        description = "Detects XenArmor Presence On Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["ProductName"] == "XenArmor All-In-One Password Recovery Pro Command-line") or
            (pe.version_info["FileDescription"] == "XenArmor All-In-One Password Recovery Pro Command-line Application") or
            (pe.version_info["OriginalFilename"] == "XenArmor All-In-One Password Recovery Pro Command-line")
        )
    )
}

rule Detect_PAExec_Exe {
    meta:
        description = "Detects PAExec Presense On Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["ProductName"] == "PAExec Application") or
            (pe.version_info["FileDescription"] == "PAExec Application")
        )
    )
}

rule Detect_PSExec_Exe {
    meta:
        description = "Detects PSExec Presence On Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        pe.version_info["CompanyName"] == "Sysinternals - www.sysinternals.com" and
        (
            (pe.version_info["FileDescription"] == "Execute processes remotely") or
            (pe.version_info["InternalName"] == "PsExec") or
            (pe.version_info["OriginalFilename"] == "psexec.c") or
            (pe.version_info["ProductName"] == "Sysinternals PsExec")
        )
    )
}

rule Detect_WinPmem_Driver {
    meta:
        description = "Detects WinPmem Driver Loading by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    strings:
        $signer_name = "Binalyze LLC" wide ascii
        $pkcs7_magic = { 30 80 06 09 2A 86 48 86 F7 0D 01 07 02 }
        $cert_publisher = "Binalyze LLC" wide ascii
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            $pkcs7_magic in (0..filesize) or
            any of them in pe.resources
        ) and (
            $cert_publisher in (0..filesize)
        )
    )
}

rule Detect_Big_Raw_File {
    meta:
        description = "Detects Big Raw Files That Are Look Like Memdump by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x505d444d and
        filesize >= 1024MB
    )
}

rule Detect_Ngrok_Exe {
    meta:
        description = "Detects Ngrok Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    strings:
        $name = "ngrok" wide ascii nocase
    
    condition:
    (
        uint16(0) == 0x5a4d and
        $name in (0..filesize)
    )
}

rule Detect_Slitheris_Exe {
    meta:
        description = "Detects Slitheris Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["CompanyName"] == "Komodo Laboratories LLC") or
            (pe.version_info["FileDescription"] == "Slitheris Network Discovery") or
            (pe.version_info["OriginalFilename"] == "slitheris.exe") or
            (pe.version_info["ProductName"] == "Slitheris Network Discovery")
        )
    )
}

rule Detect_Rclone_Exe {
    meta:
        description = "Detects Rclone Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["CompanyName"] == "https://rclone.org") or
            (pe.version_info["FileDescription"] == "Rsync for cloud storage") or
            (pe.version_info["OriginalFilename"] == "rclone.exe") or
            (pe.version_info["ProductName"] == "Rclone")
        )
    )
}

rule Detect_MeshCentral_Exe {
    meta:
        description = "Detects Mesh Central Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"
    
    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["FileDescription"] == "Mesh Agent Service") or
            (pe.version_info["OriginalFilename"] == "meshagent.exe") or
            (pe.version_info["ProductName"] == "Mesh Agent Service") or
            (pe.version_info["ProductName"] == "MeshCentral Agent") or
            (pe.version_info["FileDescription"] == "MeshCentral Background Service Agent") or
        )
    )
}

rule Detect_NirCmd_Exe {
    meta:
        description = "Detects NirCmd Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"

    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["CompanyName"] == "NirSoft") or
            (pe.version_info["FileDescription"] == "NirCmd") or
            (pe.version_info["OriginalFilename"] == "nircmd.exe") or
            (pe.version_info["ProductName"] == "Nircmd")
        )
    )
}

rule Detect_Python_Exe {
    meta:
        description = "Detects Python Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"

    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["CompanyName"] == "Python Software Foundation") or
            (pe.version_info["FileDescription"] == "Python") or
            (pe.version_info["OriginalFilename"] == "python.exe") or
            (pe.version_info["ProductName"] == "Python")
        )
    )
}

rule Detect_UltraVNC_Exe {
    meta:
        description = "Detects UltraVNC Presence On Local Machine by BIZONE"
        author = "glomo"
        date = "2025-05-27"
        threat_level = "high"

    condition:
    (
        uint16(0) == 0x5a4d and
        (
            (pe.version_info["ProductName"] == "UltraVNC") or
            (pe.version_info["FileDescription"] == "VNC server") or
            (pe.version_info["OriginalFilename"] == "WinVNC.exe")
        )
    )
}
