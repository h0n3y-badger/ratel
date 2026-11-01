"""Anti-VM / anti-sandbox / anti-emulation technique variants."""
from common import T

AV = "anti_vm"
L_STD = ("stdio.h", "stdlib.h", "string.h", "unistd.h")

# ---------------------------------------------------------------- CPUID
T("antivm.any.cpuid_hvbit.v1", "antivm.cpuid", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    if (c & (1u << 31)) exit(0);     /* hypervisor present bit */
    return 0;
}''', inc=("cpuid.h", "stdlib.h"))

T("antivm.any.cpuid_vendor_asm.v2", "antivm.cpuid", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned int r[4];
    char vendor[13];
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(0x40000000), "c"(0));
    memcpy(vendor, &r[1], 4); memcpy(vendor + 4, &r[2], 4); memcpy(vendor + 8, &r[3], 4);
    vendor[12] = 0;
    if (!strcmp(vendor, "KVMKVMKVM") || !strcmp(vendor, "VMwareVMware") || !strcmp(vendor, "Microsoft Hv") ||
        !strcmp(vendor, "VBoxVBoxVBox") || !strcmp(vendor, "XenVMMXenVMM") || !strcmp(vendor, "TCGTCGTCGTCG"))
        return 1;
    return 0;
}''', inc=("string.h",))

T("antivm.any.cpuid_vendor_table.v3", "antivm.cpuid", AV, "any", r'''
static const char *@F_vm[] = {"KVMKVMKVM\0\0\0", "VMwareVMware", "Microsoft Hv", "VBoxVBoxVBox",
    "XenVMMXenVMM", "TCGTCGTCGTCG", " lrpepyh  vr", "bhyve bhyve ", "ACRNACRNACRN", "QNXQVMBSQG"};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned a, b, c, d; char v[12];
    __cpuid(0x40000000, a, b, c, d);
    memcpy(v, &b, 4); memcpy(v + 4, &c, 4); memcpy(v + 8, &d, 4);
    for (unsigned i = 0; i < sizeof(@F_vm) / sizeof(*@F_vm); i++)
        if (!memcmp(v, @F_vm[i], 12)) { fprintf(stderr, "unsupported environment\n"); exit(1); }
    return 0;
}''', inc=("cpuid.h", "string.h", "stdio.h", "stdlib.h"))

T("antivm.any.cpuid_brand.v4", "antivm.cpuid", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned regs[12];
    for (unsigned i = 0; i < 3; i++)
        __get_cpuid(0x80000002 + i, &regs[i*4], &regs[i*4+1], &regs[i*4+2], &regs[i*4+3]);
    char brand[49]; memcpy(brand, regs, 48); brand[48] = 0;
    if (strstr(brand, "QEMU") || strstr(brand, "Virtual CPU") || strstr(brand, "KVM") || strstr(brand, "Bochs"))
        return 1;
    return 0;
}''', inc=("cpuid.h", "string.h"))

T("antivm.any.cpuid_timing.v5", "antivm.cpuid", AV, "any", r'''
static inline unsigned long long @F_rd(void) { unsigned lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((unsigned long long)hi << 32) | lo; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned long long total = 0;
    for (int i = 0; i < 10; i++) {
        unsigned a, b, c, d;
        unsigned long long t0 = @F_rd();
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0));
        total += @F_rd() - t0;
    }
    return (total / 10) > 1000;   /* cpuid traps to hypervisor -> VM exit latency */
}''')

T("antivm.any.cpuid_hvbit_asm.v6", "antivm.cpuid", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned ecx;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
    return (ecx >> 31) & 1;
}''')

# ---------------------------------------------------------------- linux artifacts
T("antivm.linux.dmi_product.v1", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[128] = {0};
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (!f) return 0;
    fgets(buf, sizeof buf, f); fclose(f);
    if (strstr(buf, "VirtualBox") || strstr(buf, "VMware") || strstr(buf, "KVM") || strstr(buf, "Standard PC (Q35") || strstr(buf, "Bochs"))
        exit(0);
    return 0;
}''', inc=L_STD)

T("antivm.linux.dmi_vendor.v2", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *files[] = {"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/bios_vendor"};
    const char *bad[] = {"QEMU", "innotek GmbH", "VMware, Inc.", "Xen", "Microsoft Corporation", "Parallels", "Oracle Corporation", "SeaBIOS"};
    char b[128];
    for (int i = 0; i < 3; i++) {
        int fd = open(files[i], O_RDONLY); if (fd < 0) continue;
        int n = read(fd, b, sizeof b - 1); close(fd);
        if (n <= 0) continue; b[n] = 0;
        for (int j = 0; j < 8; j++) if (strstr(b, bad[j])) return 1;
    }
    return 0;
}''', inc=L_STD + ("fcntl.h",))

T("antivm.linux.cpuinfo_hypervisor.v3", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char line[1024];
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    int vm = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "flags", 5) && strstr(line, " hypervisor")) { vm = 1; break; }
    fclose(f);
    return vm;
}''', inc=L_STD)

T("antivm.linux.disk_model.v4", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *paths[] = {"/proc/scsi/scsi", "/sys/block/sda/device/model", "/sys/block/vda/device/vendor"};
    char buf[2048];
    for (int i = 0; i < 3; i++) {
        FILE *f = fopen(paths[i], "r"); if (!f) continue;
        size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
        if (strstr(buf, "VBOX HARDDISK") || strstr(buf, "QEMU HARDDISK") || strstr(buf, "VMware Virtual") || strstr(buf, "0x1af4"))
            return 1;
    }
    return 0;
}''', inc=L_STD)

T("antivm.linux.guest_files.v5", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *art[] = {"/dev/vboxguest", "/dev/vboxuser", "/usr/bin/VBoxClient", "/usr/bin/vmware-toolbox-cmd",
                         "/usr/bin/vmtoolsd", "/proc/xen", "/dev/virtio-ports", "/usr/sbin/qemu-ga", "/.dockerenv"};
    for (unsigned i = 0; i < sizeof art / sizeof *art; i++)
        if (access(art[i], F_OK) == 0) return 1;
    return 0;
}''', inc=L_STD)

T("antivm.linux.detect_virt_popen.v6", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char out[64] = {0};
    FILE *p = popen("systemd-detect-virt 2>/dev/null", "r");
    if (!p) return 0;
    fgets(out, sizeof out, p);
    pclose(p);
    out[strcspn(out, "\n")] = 0;
    return out[0] && strcmp(out, "none") != 0;
}''', inc=L_STD)

T("antivm.linux.modules.v7", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char line[256];
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    int vm = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "vboxguest", 9) || !strncmp(line, "vmw_balloon", 11) || !strncmp(line, "virtio_balloon", 14) ||
            !strncmp(line, "hv_vmbus", 8) || !strncmp(line, "vmwgfx", 6) || !strncmp(line, "xen_blkfront", 12)) vm = 1;
    }
    fclose(f);
    return vm;
}''', inc=L_STD)

T("antivm.linux.sys_hypervisor.v8", "antivm.linux_artifacts", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char t[32] = {0};
    int fd = open("/sys/hypervisor/type", O_RDONLY);
    if (fd >= 0) { read(fd, t, sizeof t - 1); close(fd); }
    struct stat st;
    if (t[0] || stat("/sys/bus/vmbus", &st) == 0) _exit(1);
    return 0;
}''', inc=L_STD + ("fcntl.h", "sys/stat.h"))

# ---------------------------------------------------------------- windows registry
T("antivm.win.reg_vbox_additions.v1", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegCloseKey(k); return 1;
    }
    return 0;
}''', inc=("windows.h",), libs=("advapi32",))

T("antivm.win.reg_acpi.v2", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *keys[] = {"HARDWARE\\ACPI\\DSDT\\VBOX__", "HARDWARE\\ACPI\\FADT\\VBOX__", "HARDWARE\\ACPI\\RSDT\\VBOX__",
                          "HARDWARE\\ACPI\\DSDT\\BOCHS_", "HARDWARE\\ACPI\\DSDT\\PTLTD_"};
    for (int i = 0; i < 5; i++) {
        HKEY k;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &k) == 0) { RegCloseKey(k); ExitProcess(0); }
    }
    return 0;
}''', inc=("windows.h",), libs=("advapi32",))

T("antivm.win.reg_biosversion.v3", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char data[512] = {0}; DWORD sz = sizeof data, type;
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_QUERY_VALUE, &k)) return 0;
    RegQueryValueExA(k, "SystemBiosVersion", NULL, &type, (LPBYTE)data, &sz);
    RegCloseKey(k);
    return strstr(data, "VBOX") || strstr(data, "QEMU") || strstr(data, "BOCHS") || strstr(data, "VRTUAL");
}''', inc=("windows.h", "string.h"), libs=("advapi32",))

T("antivm.win.reg_vmware_tools.v4", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HKEY k; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ | KEY_WOW64_64KEY, &k);
    if (r == ERROR_SUCCESS) { RegCloseKey(k); return 1; }
    return 0;
}''', inc=("windows.h",), libs=("advapi32",))

T("antivm.win.reg_scsi_identifier.v5", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char v[256] = {0}; DWORD n = sizeof v;
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                     "Identifier", RRF_RT_REG_SZ, NULL, v, &n) != ERROR_SUCCESS) return 0;
    CharUpperA(v);
    return strstr(v, "VBOX") || strstr(v, "VMWARE") || strstr(v, "QEMU");
}''', inc=("windows.h", "string.h"), libs=("advapi32", "user32"))

T("antivm.win.reg_services.v6", "antivm.win_registry", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *svc[] = {"VBoxGuest", "VBoxMouse", "VBoxService", "VBoxSF", "vmci", "vmhgfs", "vmmouse", "VMTools", "xenevtchn", "vioscsi"};
    char path[256]; int n = 0;
    for (int i = 0; i < 10; i++) {
        HKEY k;
        wsprintfA(path, "SYSTEM\\CurrentControlSet\\Services\\%s", svc[i]);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k) == 0) { n++; RegCloseKey(k); }
    }
    return n;
}''', inc=("windows.h",), libs=("advapi32", "user32"))

# ---------------------------------------------------------------- windows files / devices / modules / processes
T("antivm.win.driver_files.v1", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *f[] = {"C:\\windows\\System32\\Drivers\\VBoxMouse.sys", "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
        "C:\\windows\\System32\\Drivers\\VBoxSF.sys", "C:\\windows\\System32\\Drivers\\vmhgfs.sys",
        "C:\\windows\\System32\\Drivers\\vmmouse.sys", "C:\\windows\\System32\\vboxdisp.dll", "C:\\windows\\System32\\vm3dgl.dll"};
    for (int i = 0; i < 7; i++)
        if (GetFileAttributesA(f[i]) != INVALID_FILE_ATTRIBUTES) return 1;
    return 0;
}''', inc=("windows.h",))

T("antivm.win.device_names.v2", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *dev[] = {"\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest", "\\\\.\\pipe\\VBoxMiniRdDN", "\\\\.\\HGFS", "\\\\.\\vmci", "\\\\.\\pipe\\cuckoo"};
    for (int i = 0; i < 6; i++) {
        HANDLE h = CreateFileA(dev[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }
    }
    return 0;
}''', inc=("windows.h",))

T("antivm.win.sandbox_dlls.v3", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *dlls[] = {"SbieDll.dll", "cmdvrt32.dll", "cmdvrt64.dll", "SxIn.dll", "snxhk.dll", "api_log.dll",
                          "dir_watch.dll", "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cuckoomon.dll"};
    for (int i = 0; i < 11; i++) if (GetModuleHandleA(dlls[i])) return 1;
    return 0;
}''', inc=("windows.h",))

T("antivm.win.vm_processes.v4", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *names[] = {"vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
                           "vmacthlp.exe", "prl_tools.exe", "prl_cc.exe", "xenservice.exe", "qemu-ga.exe", "vmsrvc.exe"};
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 e; e.dwSize = sizeof e; int vm = 0;
    for (BOOL ok = Process32First(s, &e); ok; ok = Process32Next(s, &e))
        for (int i = 0; i < 11; i++) if (!lstrcmpiA(e.szExeFile, names[i])) vm = 1;
    CloseHandle(s);
    return vm;
}''', inc=("windows.h", "tlhelp32.h"))

T("antivm.win.guest_dir_fopen.v5", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    FILE *f = fopen("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\uninst.exe", "rb");
    if (f) { fclose(f); return 1; }
    f = fopen("C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}''', inc=("stdio.h",))

T("antivm.win.firmware_table.v6", "antivm.win_artifacts", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    UINT sz = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (!sz) return 0;
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz);
    GetSystemFirmwareTable('RSMB', 0, b, sz);
    int vm = 0;
    const char *needles[] = {"VirtualBox", "VMware", "QEMU", "innotek", "Xen", "Parallels"};
    for (UINT i = 0; i + 10 < sz && !vm; i++)
        for (int j = 0; j < 6; j++) if (!memcmp(b + i, needles[j], strlen(needles[j]))) { vm = 1; break; }
    HeapFree(GetProcessHeap(), 0, b);
    return vm;
}''', inc=("windows.h", "string.h"))

# ---------------------------------------------------------------- MAC OUI
_OUI = '{"08:00:27", "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "52:54:00", "00:16:3e", "00:03:ff", "00:15:5d"}'
T("antivm.linux.mac_sysfs.v1", "antivm.mac", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    static const char *oui[] = ''' + _OUI + r''';
    DIR *d = opendir("/sys/class/net");
    struct dirent *e; char p[300], mac[32]; int vm = 0;
    if (!d) return 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "/sys/class/net/%s/address", e->d_name);
        FILE *f = fopen(p, "r"); if (!f) continue;
        if (fgets(mac, sizeof mac, f))
            for (int i = 0; i < 9; i++) if (!strncasecmp(mac, oui[i], 8)) vm = 1;
        fclose(f);
    }
    closedir(d);
    return vm;
}''', inc=L_STD + ("dirent.h", "strings.h"))

T("antivm.linux.mac_ioctl.v2", "antivm.mac", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *ifs[] = {"eth0", "ens33", "enp0s3", "ens3", "enp1s0"};
    int s = socket(AF_INET, SOCK_DGRAM, 0), vm = 0;
    for (int i = 0; i < 5; i++) {
        struct ifreq r; memset(&r, 0, sizeof r);
        strncpy(r.ifr_name, ifs[i], IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFHWADDR, &r) < 0) continue;
        unsigned char *m = (unsigned char *)r.ifr_hwaddr.sa_data;
        if ((m[0] == 0x08 && m[1] == 0x00 && m[2] == 0x27) || (m[0] == 0x00 && m[1] == 0x0c && m[2] == 0x29) ||
            (m[0] == 0x52 && m[1] == 0x54 && m[2] == 0x00) || (m[0] == 0x00 && m[1] == 0x50 && m[2] == 0x56)) vm = 1;
    }
    close(s);
    return vm;
}''', inc=L_STD + ("sys/ioctl.h", "sys/socket.h", "net/if.h"))

T("antivm.linux.mac_getifaddrs.v3", "antivm.mac", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    static const unsigned char oui[][3] = {{0x08,0x00,0x27},{0x00,0x0c,0x29},{0x00,0x50,0x56},{0x52,0x54,0x00},{0x00,0x16,0x3e},{0x00,0x15,0x5d}};
    struct ifaddrs *ia, *p; int vm = 0;
    if (getifaddrs(&ia)) return 0;
    for (p = ia; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_PACKET) continue;
        struct sockaddr_ll *ll = (struct sockaddr_ll *)p->ifa_addr;
        for (int i = 0; i < 6; i++) if (!memcmp(ll->sll_addr, oui[i], 3)) vm = 1;
    }
    freeifaddrs(ia);
    return vm;
}''', inc=L_STD + ("ifaddrs.h", "sys/socket.h", "netpacket/packet.h"))

T("antivm.win.mac_adaptersinfo.v4", "antivm.mac", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    IP_ADAPTER_INFO buf[16]; ULONG len = sizeof buf; int vm = 0;
    if (GetAdaptersInfo(buf, &len) != ERROR_SUCCESS) return 0;
    for (PIP_ADAPTER_INFO a = buf; a; a = a->Next) {
        BYTE *m = a->Address;
        if ((m[0] == 0x08 && m[1] == 0x00 && m[2] == 0x27) || (m[0] == 0x00 && m[1] == 0x05 && m[2] == 0x69) ||
            (m[0] == 0x00 && m[1] == 0x0C && m[2] == 0x29) || (m[0] == 0x00 && m[1] == 0x1C && m[2] == 0x14) ||
            (m[0] == 0x00 && m[1] == 0x50 && m[2] == 0x56)) vm = 1;
    }
    return vm;
}''', inc=("windows.h", "iphlpapi.h"), libs=("iphlpapi",))

T("antivm.win.mac_adaptersaddr.v5", "antivm.mac", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    ULONG sz = 15000; int vm = 0;
    PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)malloc(sz);
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, aa, &sz) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES p = aa; p; p = p->Next) {
            char mac[18];
            sprintf(mac, "%02X:%02X:%02X", p->PhysicalAddress[0], p->PhysicalAddress[1], p->PhysicalAddress[2]);
            if (!strcmp(mac, "08:00:27") || !strcmp(mac, "00:0C:29") || !strcmp(mac, "00:50:56") || !strcmp(mac, "00:15:5D")) vm = 1;
        }
    }
    free(aa);
    return vm;
}''', inc=("winsock2.h", "ws2tcpip.h", "windows.h", "iphlpapi.h", "stdio.h", "stdlib.h", "string.h"), libs=("iphlpapi", "ws2_32"))

# ---------------------------------------------------------------- resource checks (cores/RAM/disk/uptime/screen)
T("antivm.linux.cores_ram.v1", "antivm.resources", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    struct sysinfo si; sysinfo(&si);
    unsigned long long ram = (unsigned long long)si.totalram * si.mem_unit;
    if (cpus < 2 || ram < 2ULL * 1024 * 1024 * 1024) { puts("ok"); exit(0); }  /* likely sandbox: bail out */
    return 0;
}''', inc=L_STD + ("sys/sysinfo.h",))

T("antivm.linux.disk_size.v2", "antivm.resources", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct statvfs v;
    if (statvfs("/", &v)) return 0;
    unsigned long long total = (unsigned long long)v.f_blocks * v.f_frsize;
    return total < 60ULL * 1000 * 1000 * 1000;   /* < 60 GB disk: analysis VM */
}''', inc=L_STD + ("sys/statvfs.h",))

T("antivm.linux.uptime.v3", "antivm.resources", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    double up = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (f) { fscanf(f, "%lf", &up); fclose(f); }
    if (up > 0 && up < 600.0) _exit(0);   /* fresh boot -> sandbox */
    return 0;
}''', inc=L_STD)

T("antivm.win.mem_cpu.v4", "antivm.resources", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof ms;
    GlobalMemoryStatusEx(&ms);
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024 || si.dwNumberOfProcessors < 2) ExitProcess(0);
    return 0;
}''', inc=("windows.h",))

T("antivm.win.disk_size.v5", "antivm.resources", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    ULARGE_INTEGER total, freeb;
    if (!GetDiskFreeSpaceExA("C:\\", NULL, &total, &freeb)) return 0;
    if (total.QuadPart / (1024ULL * 1024 * 1024) < 80) return 1;
    return 0;
}''', inc=("windows.h",))

T("antivm.win.uptime.v6", "antivm.resources", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    ULONGLONG up = GetTickCount64();
    if (up < 12ULL * 60 * 1000) { Sleep(1000); return 1; }
    return 0;
}''', inc=("windows.h",))

T("antivm.win.screen_res.v7", "antivm.resources", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    if (w < 1024 || h < 768) return 1;
    if (GetSystemMetrics(SM_CMONITORS) < 1) return 1;
    return 0;
}''', inc=("windows.h",), libs=("user32",))

# ---------------------------------------------------------------- sleep skew / stalling
T("antivm.linux.sleep_skew.v1", "antivm.sleep_skew", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct timespec a, b;
    clock_gettime(CLOCK_REALTIME, &a);
    sleep(3);
    clock_gettime(CLOCK_REALTIME, &b);
    if (b.tv_sec - a.tv_sec < 2) exit(0);   /* sleep was fast-forwarded */
    return 0;
}''', inc=L_STD + ("time.h",))

T("antivm.linux.nanosleep_rdtsc.v2", "antivm.sleep_skew", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned lo, hi; unsigned long long t0, t1;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); t0 = ((unsigned long long)hi << 32) | lo;
    struct timespec ts = {1, 500000000};
    nanosleep(&ts, NULL);
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); t1 = ((unsigned long long)hi << 32) | lo;
    return (t1 - t0) < 1000000000ULL;   /* < ~1e9 cycles over 1.5s => accelerated */
}''', inc=("time.h",))

T("antivm.win.sleep_tick.v3", "antivm.sleep_skew", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    DWORD t0 = GetTickCount();
    Sleep(5000);
    if (GetTickCount() - t0 < 4500) ExitProcess(0);
    return 0;
}''', inc=("windows.h",))

T("antivm.win.stall_long.v4", "antivm.sleep_skew", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    /* outlast the sandbox timeout */
    for (int i = 0; i < 60; i++) Sleep(10000);
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(ev, 300000);
    CloseHandle(ev);
    return 0;
}''', inc=("windows.h",))

T("antivm.any.busy_stall.v5", "antivm.sleep_skew", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    time_t end = time(NULL) + 180;
    volatile unsigned long spin = 0;
    while (time(NULL) < end) spin++;   /* busy-wait instead of Sleep to dodge sleep patching */
    return (int)(spin & 1);
}''', inc=("time.h",))

T("antivm.win.ntdelay_qpc.v6", "antivm.sleep_skew", AV, "windows", r'''
typedef LONG (NTAPI *@F_nde)(BOOLEAN, PLARGE_INTEGER);
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_nde d = (@F_nde)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
    LARGE_INTEGER f, a, b, iv; iv.QuadPart = -30000000LL;   /* 3s */
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    if (d) d(FALSE, &iv);
    QueryPerformanceCounter(&b);
    return (double)(b.QuadPart - a.QuadPart) / f.QuadPart < 2.5;
}''', inc=("windows.h",))

T("antivm.linux.select_stall.v7", "antivm.sleep_skew", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    time_t before = time(NULL);
    struct timeval tv = {240, 0};
    select(0, NULL, NULL, NULL, &tv);
    return time(NULL) - before < 200;
}''', inc=("sys/select.h", "time.h"))

# ---------------------------------------------------------------- privileged-instruction tricks
T("antivm.any.redpill_sidt.v1", "antivm.instr", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char idtr[10] = {0};
    __asm__ volatile("sidt %0" : "=m"(idtr));
    return idtr[sizeof(void *) == 8 ? 9 : 5] > 0xd0;   /* relocated IDT base */
}''')

T("antivm.any.sgdt.v2", "antivm.instr", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char gdtr[10] = {0};
    __asm__ volatile("sgdt %0" : "=m"(gdtr));
    return gdtr[sizeof(void *) == 8 ? 9 : 5] == 0xff;
}''')

T("antivm.any.sldt.v3", "antivm.instr", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned short ldt = 0;
    __asm__ volatile("sldt %0" : "=m"(ldt));
    if (ldt != 0) return 1;
    return 0;
}''')

T("antivm.any.str_tr.v4", "antivm.instr", AV, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char mem[4] = {0};
    __asm__ volatile("str %0" : "=m"(*(unsigned short *)mem));
    return (mem[0] == 0x00 && mem[1] == 0x40);   /* VMware task register signature */
}''')

T("antivm.linux.vmware_backdoor.v5", "antivm.instr", AV, "linux", r'''
static sigjmp_buf @F_jb;
static void @F_segv(int s) { siglongjmp(@F_jb, 1); }
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned int a = 0x564D5868 /* 'VMXh' */, b = 0, c = 10, d = 0x5658 /* 'VX' */;
    signal(SIGSEGV, @F_segv);
    if (sigsetjmp(@F_jb, 1)) return 0;
    __asm__ volatile("inl %%dx, %%eax" : "+a"(a), "+b"(b), "+c"(c), "+d"(d));
    return b == 0x564D5868;
}''', inc=("signal.h", "setjmp.h"))

T("antivm.win.vmware_backdoor.v6", "antivm.instr", AV, "windows", r'''
static volatile int @F_fault;
static LONG CALLBACK @F_veh(PEXCEPTION_POINTERS e) {
    @F_fault = 1;
#ifdef _WIN64
    e->ContextRecord->Rip += 1;
#else
    e->ContextRecord->Eip += 1;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned int a = 0x564D5868, b = 0, c = 0x0A, d = 0x5658;
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    __asm__ volatile("inl %%dx, %%eax" : "+a"(a), "+b"(b), "+c"(c), "+d"(d));
    RemoveVectoredExceptionHandler(h);
    return !@F_fault && b == 0x564D5868;
}''', inc=("windows.h",))

T("antivm.linux.vmcall_probe.v7", "antivm.instr", AV, "linux", r'''
static sigjmp_buf @F_jb;
static void @F_h(int s) { siglongjmp(@F_jb, 1); }
__attribute__((noinline)) int @F(int argc, char **argv) {
    signal(SIGILL, @F_h); signal(SIGSEGV, @F_h);
    if (sigsetjmp(@F_jb, 1)) return 0;
    __asm__ volatile(".byte 0x0f, 0x01, 0xc1");   /* vmcall */
    return 1;
}''', inc=("signal.h", "setjmp.h"))

# ---------------------------------------------------------------- sandbox identity / user activity
_SBUSERS = '{"sandbox", "malware", "maltest", "virus", "sample", "cuckoo", "analyst", "john", "test", "currentuser", "wdagutilityaccount", "hapubws", "emily", "peter wilson", "timmy"}'
T("antivm.linux.username.v1", "antivm.sandbox_identity", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    static const char *bad[] = ''' + _SBUSERS + r''';
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return 0;
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) if (!strcasecmp(pw->pw_name, bad[i])) exit(0);
    return 0;
}''', inc=L_STD + ("pwd.h", "strings.h", "sys/types.h"))

T("antivm.linux.hostname.v2", "antivm.sandbox_identity", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char h[256] = {0};
    gethostname(h, sizeof h - 1);
    for (char *p = h; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
    return strstr(h, "sandbox") || strstr(h, "malware") || strstr(h, "cuckoo") || strstr(h, "analysis") || strstr(h, "remnux");
}''', inc=L_STD)

T("antivm.win.username.v3", "antivm.sandbox_identity", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    static const char *bad[] = ''' + _SBUSERS + r''';
    char u[257]; DWORD n = sizeof u;
    if (!GetUserNameA(u, &n)) return 0;
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) if (!lstrcmpiA(u, bad[i])) return 1;
    return 0;
}''', inc=("windows.h",), libs=("advapi32",))

T("antivm.win.computername.v4", "antivm.sandbox_identity", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *bad[] = {"SANDBOX", "7SILVIA", "HANSPETER-PC", "JOHN-PC", "MUELLER-PC", "WIN7-TRAPS", "FORTINET", "TEQUILABOOMBOOM", "KLONE_X64-PC"};
    char c[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = sizeof c;
    GetComputerNameA(c, &n);
    for (int i = 0; i < 9; i++) if (!lstrcmpiA(c, bad[i])) ExitProcess(0);
    return 0;
}''', inc=("windows.h",))

T("antivm.win.cursor_activity.v5", "antivm.sandbox_identity", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    POINT a, b;
    GetCursorPos(&a);
    Sleep(30000);
    GetCursorPos(&b);
    if (a.x == b.x && a.y == b.y) return 1;   /* no human moving the mouse */
    LASTINPUTINFO li; li.cbSize = sizeof li; GetLastInputInfo(&li);
    return (GetTickCount() - li.dwTime) > 600000;
}''', inc=("windows.h",), libs=("user32",))

T("antivm.win.process_count.v6", "antivm.sandbox_identity", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 e; e.dwSize = sizeof e; int n = 0;
    for (BOOL ok = Process32First(s, &e); ok; ok = Process32Next(s, &e)) n++;
    CloseHandle(s);
    return n < 50;   /* real desktops run many processes */
}''', inc=("windows.h", "tlhelp32.h"))

T("antivm.linux.process_count.v7", "antivm.sandbox_identity", AV, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    DIR *d = opendir("/proc"); struct dirent *e; int n = 0;
    if (!d) return 0;
    while ((e = readdir(d))) if (e->d_name[0] >= '1' && e->d_name[0] <= '9') n++;
    closedir(d);
    if (n < 40 && !getenv("DISPLAY") && !getenv("WAYLAND_DISPLAY")) exit(0);
    return 0;
}''', inc=L_STD + ("dirent.h",))

T("antivm.win.recent_files.v8", "antivm.sandbox_identity", AV, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char path[MAX_PATH]; WIN32_FIND_DATAA fd; int n = 0;
    if (!GetEnvironmentVariableA("APPDATA", path, MAX_PATH)) return 0;
    lstrcatA(path, "\\Microsoft\\Windows\\Recent\\*");
    HANDLE h = FindFirstFileA(path, &fd);
    if (h != INVALID_HANDLE_VALUE) { do n++; while (FindNextFileA(h, &fd)); FindClose(h); }
    return n < 20;
}''', inc=("windows.h",))
