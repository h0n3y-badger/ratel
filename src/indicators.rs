//! Static indicator tables. Everything here is data: API names, strings and
//! constants that show up in code which detects debuggers / VMs, hides itself,
//! unpacks payloads, does crypto, or talks to the network.
//!
//! Matching is case-insensitive for strings and exact for API names.

/// API groups. A binary that imports (or names, for dynamically resolved APIs)
/// one of these gets a count in the matching feature.
pub struct ApiGroup {
    pub feature: &'static str,
    pub apis: &'static [&'static str],
}

pub const API_GROUPS: &[ApiGroup] = &[
    ApiGroup {
        feature: "api_antidbg",
        apis: &[
            "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "ZwQueryInformationProcess", "NtSetInformationThread", "ZwSetInformationThread",
            "DebugActiveProcess", "NtQueryObject", "GetThreadContext", "NtQuerySystemInformation",
            "ZwQuerySystemInformation", "DbgUiRemoteBreakin", "NtYieldExecution", "BlockInput", "ptrace",
            // IsDebuggerPresent / SetUnhandledExceptionFilter / OutputDebugString are imported by the
            // MSVC CRT in nearly every Windows binary; they are kept as separate key-API features only.
        ],
    },
    ApiGroup {
        feature: "api_timing",
        apis: &[
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "timeGetTime",
            "NtDelayExecution", "Sleep", "SleepEx", "GetSystemTimeAsFileTime", "clock_gettime",
            "gettimeofday", "nanosleep", "usleep", "sleep", "clock_nanosleep",
        ],
    },
    ApiGroup {
        feature: "api_sysinfo",
        apis: &[
            "GetSystemInfo", "GetNativeSystemInfo", "GlobalMemoryStatusEx", "GetComputerNameA",
            "GetComputerNameW", "GetComputerNameExA", "GetComputerNameExW", "GetUserNameA", "GetUserNameW",
            "GetAdaptersInfo", "GetAdaptersAddresses", "GetDiskFreeSpaceExA", "GetDiskFreeSpaceExW",
            "DeviceIoControl", "SetupDiGetClassDevsA", "SetupDiGetClassDevsW",
            "SetupDiGetDeviceRegistryPropertyA", "SetupDiGetDeviceRegistryPropertyW", "GetCursorPos",
            "GetLastInputInfo", "EnumProcesses", "CreateToolhelp32Snapshot", "Process32First",
            "Process32FirstW", "Process32Next", "Process32NextW", "Module32First", "Module32FirstW",
            "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
            "EnumSystemFirmwareTables", "GetSystemFirmwareTable", "GetModuleHandleA", "GetModuleHandleW",
            "WNetGetProviderNameA", "WNetGetProviderNameW", "sysinfo", "get_nprocs", "get_nprocs_conf",
            "uname", "getifaddrs", "if_nameindex",
        ],
    },
    ApiGroup {
        feature: "api_dynres",
        apis: &[
            "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "LdrLoadDll", "LdrGetProcedureAddress", "LdrGetDllHandle", "dlopen", "dlsym", "dlvsym",
        ],
    },
    ApiGroup {
        feature: "api_mem",
        apis: &[
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory", "WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
            "SetThreadContext", "ResumeThread", "RtlDecompressBuffer", "mprotect", "memfd_create",
            "fexecve", "execveat", "process_vm_writev",
        ],
    },
    ApiGroup {
        feature: "api_net",
        apis: &[
            "socket", "connect", "bind", "listen", "accept", "accept4", "send", "recv", "sendto",
            "recvfrom", "sendmsg", "recvmsg", "getaddrinfo", "gethostbyname", "inet_addr", "inet_pton",
            "inet_ntoa", "htons", "WSAStartup", "WSASocketA", "WSASocketW", "WSAConnect", "WSASend",
            "WSARecv", "closesocket", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
            "InternetOpenUrlW", "InternetConnectA", "InternetConnectW", "InternetReadFile",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen",
            "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
            "WinHttpReadData", "URLDownloadToFileA", "URLDownloadToFileW", "DnsQuery_A", "DnsQuery_W",
            "DnsQuery_UTF8", "res_query", "res_search", "curl_easy_init", "curl_easy_perform",
            "SSL_connect", "SSL_write",
        ],
    },
    ApiGroup {
        feature: "api_crypto",
        apis: &[
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
            "CryptCreateHash", "CryptHashData", "CryptDeriveKey", "CryptGenKey", "CryptImportKey",
            "CryptGenRandom", "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
            "BCryptGenerateSymmetricKey", "BCryptHashData", "BCryptCreateHash", "BCryptGenRandom",
            "BCryptImportKeyPair", "CryptStringToBinaryA", "CryptBinaryToStringA",
            "SystemFunction032", "SystemFunction036", "EVP_EncryptInit_ex", "EVP_DecryptInit_ex",
            "EVP_CipherInit_ex", "EVP_aes_256_cbc", "EVP_aes_128_cbc", "EVP_aes_256_gcm",
            "EVP_chacha20", "EVP_DigestInit_ex", "AES_set_encrypt_key", "AES_encrypt", "RSA_public_encrypt",
            "RAND_bytes", "crypto_secretbox", "crypto_box", "gcry_cipher_open",
        ],
    },
    ApiGroup {
        feature: "api_proc",
        apis: &[
            "CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "ShellExecuteA", "ShellExecuteW",
            "ShellExecuteExA", "ShellExecuteExW", "WinExec", "OpenProcess", "TerminateProcess",
            "system", "popen", "execve", "execv", "execvp", "execl", "execlp", "posix_spawn", "fork",
            "vfork", "kill", "daemon", "setsid",
        ],
    },
];

/// Individual APIs that are strong single signals; each gets its own 0/1 feature.
pub const KEY_APIS: &[(&str, &[&str])] = &[
    ("api_isdebuggerpresent", &["IsDebuggerPresent"]),
    ("api_checkremotedbg", &["CheckRemoteDebuggerPresent"]),
    ("api_ntqip", &["NtQueryInformationProcess", "ZwQueryInformationProcess"]),
    ("api_ntsetinfothread", &["NtSetInformationThread", "ZwSetInformationThread"]),
    ("api_outputdebugstring", &["OutputDebugStringA", "OutputDebugStringW"]),
    ("api_ptrace", &["ptrace"]),
    ("api_prctl", &["prctl"]),
    ("api_getprocaddress", &["GetProcAddress", "LdrGetProcedureAddress", "dlsym"]),
    ("api_virtualprotect", &["VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory", "mprotect"]),
    ("api_virtualalloc", &["VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory"]),
    ("api_memfd", &["memfd_create", "fexecve", "execveat"]),
    ("api_injection", &["WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection", "process_vm_writev"]),
    ("api_toolhelp", &["CreateToolhelp32Snapshot", "Process32First", "Process32FirstW", "EnumProcesses"]),
    ("api_memstatus", &["GlobalMemoryStatusEx", "GetSystemInfo", "GetNativeSystemInfo", "sysinfo", "get_nprocs"]),
    ("api_firmware", &["EnumSystemFirmwareTables", "GetSystemFirmwareTable", "SetupDiGetClassDevsA", "SetupDiGetClassDevsW"]),
    ("api_userinput", &["GetCursorPos", "GetLastInputInfo"]),
    ("api_http", &["InternetOpenA", "InternetOpenW", "WinHttpOpen", "URLDownloadToFileA",
        "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW", "curl_easy_perform"]),
    ("api_socket", &["socket", "WSASocketA", "WSASocketW", "WSAStartup", "connect"]),
    ("api_dns", &["getaddrinfo", "gethostbyname", "DnsQuery_A", "DnsQuery_W", "res_query"]),
    ("api_wincrypt", &["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
        "CryptAcquireContextA", "CryptAcquireContextW", "BCryptOpenAlgorithmProvider", "SystemFunction032"]),
    ("api_openssl", &["EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex", "AES_encrypt", "RSA_public_encrypt"]),
];

/// Case-insensitive string indicator sets, matched over the raw file (ASCII and UTF-16LE).
pub struct StrGroup {
    pub feature: &'static str,
    pub pats: &'static [&'static str],
}

pub const STR_GROUPS: &[StrGroup] = &[
    StrGroup {
        feature: "str_vm_vendor",
        pats: &[
            "KVMKVMKVM", "VMwareVMware", "Microsoft Hv", "VBoxVBoxVBox", "TCGTCGTCGTCG", "XenVMMXenVMM",
            " lrpepyh vr", "prl hyperv", "bhyve bhyve", "ACRNACRNACRN", "QNXQVMBSQG",
        ],
    },
    StrGroup {
        feature: "str_vm_artifact",
        pats: &[
            "vbox", "virtualbox", "vboxuser", "vboxvideo", "vmware", "qemu", "bochs", "parallels", "innotek", "xen ",
            "virtual machine", "vboxguest", "vboxmouse", "vboxsf", "vboxservice", "vboxtray",
            "vmtoolsd", "vmhgfs", "vmmouse", "vmci", "vm3dmp", "vmrawdsk", "vmusbmouse", "vmx_svga",
            "prl_cc", "prl_tools", "qemu-ga", "virtio", "hyper-v", "hyperv", "/sys/class/dmi/id",
            "product_name", "sys_vendor", "board_vendor", "bios_vendor", "/proc/scsi/scsi",
            "hardware\\acpi\\dsdt", "hardware\\description\\system", "systembiosversion",
            "videobiosversion", "08:00:27", "00:0c:29", "00:50:56", "00:05:69", "00:1c:14",
            "52:54:00", "00:16:3e", "00:1c:42", "080027", "000c29", "005056", "wine_get_unix_file_name",
            "wine_get_version", "/.dockerenv", "/run/.containerenv", "container=", "systemd-detect-virt",
            "virt-what", "/sys/hypervisor", "hypervisor", "vmware tools", "vboxclient",
        ],
    },
    StrGroup {
        feature: "str_sandbox",
        pats: &[
            "sbiedll", "sandboxie", "cuckoo", "cuckoomon", "joebox", "joe sandbox", "any.run",
            "anubis", "threatexpert", "cwsandbox", "sxin.dll", "api_log.dll", "dir_watch.dll",
            "pstorec.dll", "vmcheck.dll", "wpespy.dll", "snxhk.dll", "cmdvrt32.dll", "avghookx.dll",
            "\\sample.exe", "c:\\sample", "c:\\analysis", "john doe", "hapubws", "hong lee",
            "milozs", "peter wilson", "maltest", "malnetvm", "wdagutilityaccount", "fakenet", "inetsim",
            "vboxuser", "sandboxie", "cuckoo1", "vmware_user",
        ],
    },
    StrGroup {
        feature: "str_dbg_tools",
        pats: &[
            "ollydbg", "x64dbg", "x32dbg", "windbg", "immunity debugger", "idaq", "ida64", "ida.exe",
            "ghidra", "radare2", "r2frida", "frida", "gdbserver", "processhacker", "procmon",
            "procexp", "wireshark", "fiddler", "httpdebugger", "scylla", "importrec", "lordpe",
            "pestudio", "dumpcap", "regmon", "filemon", "tcpview", "autoruns", "sysinternals",
            "cheat engine", "dnspy", "de4dot", "ltrace", "strace", "/usr/bin/gdb", "edb-debugger",
            "titanhide", "scyllahide", "hyperhide",
        ],
    },
    StrGroup {
        feature: "str_dbg_checks",
        pats: &[
            "tracerpid", "/proc/self/status", "ld_preload", "ld_audit", "/proc/self/maps",
            "/proc/self/fd", "beingdebugged", "ntglobalflag", "heapflags", "debugobject",
            "processdebugport", "processdebugflags", "processdebugobjecthandle",
            "threadhidefromdebugger", "kernel_debugger", "systemkerneldebuggerinformation",
            "/proc/sys/kernel/yama/ptrace_scope", "gum-js-loop", "gmain", "linjector",
            "re.frida.server", "frida-agent", "/proc/self/task", "dbgbreakpoint", "csrss.exe",
        ],
    },
    StrGroup {
        feature: "str_net",
        pats: &[
            "http://", "https://", "user-agent", "mozilla/", "content-type", "content-length",
            "post /", "get /", "host:", "connection: keep-alive", "ws://", "wss://", ".onion",
            ".i2p", "/gate.php", "/panel/", "ftp://", "tcp://", "accept-encoding", "authorization:",
            "x-forwarded-for", "smtp", "irc ", "privmsg", "telegram", "discord.com/api",
            "pastebin.com", "raw.githubusercontent", "ngrok", "duckdns", "no-ip",
        ],
    },
    StrGroup {
        feature: "str_crypto",
        pats: &[
            "-----begin", "aes", "rsa", "chacha", "salsa20", "rc4", "blowfish", "twofish",
            "serpent", "camellia", "ecdh", "ed25519", "curve25519", "sha256", "sha-256", "sha512",
            "hmac", "pbkdf2", "scrypt", "argon2", "bcrypt", "x25519", "poly1305", "gcm",
            "microsoft enhanced cryptographic", "microsoft enhanced rsa and aes",
        ],
    },
    StrGroup {
        feature: "str_exec",
        pats: &[
            "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "-encodedcommand", "rundll32",
            "regsvr32", "mshta", "wscript", "cscript", "schtasks", "crontab", "/etc/cron",
            "/etc/rc.local", "systemctl", "/etc/ld.so.preload", "currentversion\\run",
            "/dev/shm", "/tmp/.", "chmod +x", "wget ", "curl ", "bitsadmin", "certutil",
        ],
    },
];

/// API names that, when found as *strings* but not imported, indicate dynamic
/// resolution (GetProcAddress / dlsym by name).
pub const DYN_API_NAMES: &[&str] = &[
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "ZwQueryInformationProcess", "NtSetInformationThread", "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "WinExec", "ShellExecuteA", "CreateProcessA",
    "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "WSAStartup", "WinHttpOpen",
    "CryptDecrypt", "CryptEncrypt", "BCryptDecrypt", "RtlDecompressBuffer", "NtDelayExecution",
    "GetTickCount", "Sleep", "GlobalMemoryStatusEx", "CreateToolhelp32Snapshot", "ptrace",
    "memfd_create", "mprotect", "fexecve", "OutputDebugStringA", "GetSystemFirmwareTable",
    "NtQuerySystemInformation", "NtSetInformationThread", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
];

/// Byte-pattern crypto constants (findcrypt-style), LE unless noted.
pub const CRYPTO_CONSTS: &[(&str, &[u8])] = &[
    ("cc_aes_sbox", &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b]),
    ("cc_aes_invsbox", &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e]),
    ("cc_aes_ttable", &[0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8]),
    ("cc_aes_ttable", &[0xc6, 0x63, 0x63, 0xa5, 0xf8, 0x7c, 0x7c, 0x84]),
    ("cc_sha256", &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71]),
    ("cc_sha256", &[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91]),
    ("cc_sha256", &[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb]),
    ("cc_sha512", &[0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42]),
    ("cc_sha512", &[0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a]),
    ("cc_md5", &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8]),
    ("cc_md5", &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98]),
    ("cc_crc32", &[0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee]),
    ("cc_blowfish", &[0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85]),
    ("cc_chacha", b"expand 32-byte k"),
    ("cc_chacha", b"expand 16-byte k"),
    ("cc_des", &[58, 50, 42, 34, 26, 18, 10, 2, 60, 52]),
    ("cc_rsa_oid", &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
    ("cc_base64", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
];

/// 32-bit immediates in code that point at a crypto/hash primitive.
pub const CRYPTO_IMMS: &[(u32, &str)] = &[
    (0x9E37_79B9, "tea"), (0x61C8_8647, "tea"), (0xC6EF_3720, "tea"),
    (0x428A_2F98, "sha256"), (0x6A09_E667, "sha256"), (0xBB67_AE85, "sha256"), (0x7137_4491, "sha256"),
    (0x5A82_7999, "sha1"), (0x6ED9_EBA1, "sha1"), (0x8F1B_BCDC, "sha1"), (0xCA62_C1D6, "sha1"),
    (0xD76A_A478, "md5"), (0xE8C7_B756, "md5"), (0x6745_2301, "md5"), (0xEFCD_AB89, "md5"),
    (0x6170_7865, "chacha"), (0x3320_646E, "chacha"), (0x7962_2D32, "chacha"), (0x6B20_6574, "chacha"),
    (0xEDB8_8320, "crc32"), (0x04C1_1DB7, "crc32"), (0x82F6_3B78, "crc32"),
];

/// Immediates that only show up in VM/hypervisor probing.
pub const VM_IMMS: &[(u32, &str)] = &[
    (0x564D_5868, "vmware_magic_VMXh"), (0x5658, "vmware_port_VX"), (0x5659, "vmware_port_VY"),
    (0x4000_0000, "cpuid_hv_leaf"), (0x4B4D_564B, "KVMK"), (0x7263_694D, "Micr"), (0x6177_4D56, "VMwa"),
    (0x786F_4256, "VBox"), (0x5447_4354, "TCGT"),
];

/// Hash-algorithm constants common in API hashing (ror13, djb2, FNV, CRC-style).
pub const APIHASH_IMMS: &[u32] = &[0x811C_9DC5, 0x0100_0193, 0x0000_1505, 0x0000_0D11];

/// Section names left behind by packers / protectors.
pub const PACKER_SECTIONS: &[&str] = &[
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".asp", ".vmp0", ".vmp1", ".vmp2",
    ".themida", ".winlice", ".enigma1", ".enigma2", ".petite", ".mpress1", ".mpress2", ".nsp0",
    ".nsp1", ".nsp2", ".packed", ".perplex", ".pec", ".pec1", ".pec2", ".yp", ".boom", ".ccg",
    ".charmve", ".ecode", ".edata_", "pebundle", ".rlpack", ".rmnet", ".seau", ".sforce3",
    ".spack", ".svkp", ".taz", ".tsuarch", ".tsustub", ".kkrunchy", "bitarts", "fsg!", ".mew",
    ".neolite", ".gentee", ".imrsiv", ".arxan",
];

/// Standard section names; anything else counts as "nonstandard".
pub const STD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".tls", ".pdata",
    ".xdata", ".crt", ".CRT", ".debug", ".init", ".fini", ".plt", ".got", ".got.plt", ".dynamic",
    ".dynsym", ".dynstr", ".rodata", ".eh_frame", ".eh_frame_hdr", ".gcc_except_table", ".interp",
    ".note", ".gnu", ".rela", ".rel", ".init_array", ".fini_array", ".symtab", ".strtab",
    ".shstrtab", ".comment", ".tbss", ".tdata", ".jcr", ".ctors", ".dtors", ".data.rel.ro",
    ".gnu_debuglink", ".gnu_debugdata", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_r",
    ".gnu.version_d", ".plt.got", ".plt.sec", ".buildid", ".sdata", ".00cfg", ".gfids", ".giats",
    ".retplne", ".voltbl", ".didat", ".orpc", ".textbss", "/", ".gehcont", ".fptable", ".stab",
    ".go.buildinfo", ".gopclntab", ".noptrdata", ".noptrbss", ".typelink", ".itablink",
    ".gosymtab", ".lrodata", ".ldata", ".lbss", ".tm_clone_table", ".preinit_array", ".relro_padding",
];

/// "Role" indicators: code that *implements* the thing an evasion check looks for.
/// A hypervisor contains every VM vendor string because it emulates those devices;
/// a debugger reads /proc/<pid>/status and talks ptrace because that is its job.
/// A role only discounts the capabilities it excuses, needs several distinct
/// indicators, and is ignored when the binary also hides itself (see report.rs).
pub struct RoleDef {
    pub name: &'static str,
    pub feature: &'static str,
    pub excuses: &'static [&'static str],
    pub min: usize,
    pub pats: &'static [&'static str],
}

pub const ROLES: &[RoleDef] = &[
    RoleDef {
        name: "hypervisor", feature: "role_hypervisor", excuses: &["anti_vm"], min: 2,
        pats: &[
            "/dev/kvm", "/dev/vhost-net", "/dev/vhost-vsock", "/dev/vfio/vfio", "/dev/vboxdrv", "/dev/vboxdrvu",
            "\\\\.\\VBoxDrv", "/dev/vmmon", "KVM_RUN", "KVM_CREATE_VM", "KVM_CAP_", "kvm_run", "virConnectOpen",
            "virConnectOpenAuth", "libvirt.so", "WHvCreatePartition", "WinHvPlatform", "VBoxVMM", "VMMR3",
            "hvf_vcpu", "Hypervisor.framework",
        ],
    },
    RoleDef {
        name: "container-runtime", feature: "role_container", excuses: &["anti_vm"], min: 3,
        pats: &[
            "pivot_root", "/proc/self/setgroups", "cgroup.procs", "runtime-spec", "/run/containerd",
            "lowerdir=", "newuidmap", "newgidmap", "/var/lib/docker", "/var/lib/containers", "/var/lib/lxc",
            "seccomp_rule_add", "oci-runtime", "io.containerd",
        ],
    },
    RoleDef {
        name: "debugger", feature: "role_debugger", excuses: &["anti_debug"], min: 3,
        pats: &[
            "libthread_db", "td_ta_new", "td_thr_get_info", "/proc/%d/mem", "/proc/%u/mem", "/proc/%ld/mem",
            "PTRACE_GETREGS", "PTRACE_PEEKUSER", "PTRACE_GETREGSET", "PTRACE_SETOPTIONS", "PTRACE_SYSCALL",
            "watchpoint", "hardware breakpoint", "single-step", "singlestep", "DW_TAG_", "DW_AT_", "debuginfod",
            "SymInitialize", "StackWalk64", "vgdb", "DEBUG_EVENT",
        ],
    },
    RoleDef {
        name: "wine", feature: "role_wine", excuses: &["anti_vm", "anti_debug"], min: 2,
        pats: &[
            "Wine builtin DLL", "Wine placeholder DLL", "wine_server_call", "__wine_", "WINEPREFIX", "WINEDEBUG",
            "WINESERVER", "wineserver", "WINELOADER",
        ],
    },
];
