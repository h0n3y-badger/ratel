"""Anti-debugging technique variants (Linux + Windows)."""
from common import T

AD = "anti_debug"
L_STD = ("stdio.h", "stdlib.h", "string.h", "unistd.h")

# ---------------------------------------------------------------- linux: ptrace
T("antidbg.linux.ptrace_traceme.v1", "antidbg.ptrace", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        fputs("debugger detected\n", stderr);
        exit(1);
    }
    return 0;
}''', inc=L_STD + ("sys/ptrace.h",))

T("antidbg.linux.ptrace_syscall.v2", "antidbg.ptrace", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    long r = syscall(SYS_ptrace, 0L, 0L, 0L, 0L);
    if (r < 0) _exit(3);
    return (int)r;
}''', inc=L_STD + ("sys/syscall.h",))

T("antidbg.linux.ptrace_asm.v3", "antidbg.ptrace", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    long r;
    __asm__ volatile("mov $101, %%eax\n\txor %%edi, %%edi\n\txor %%esi, %%esi\n\t"
                     "xor %%edx, %%edx\n\txor %%r10d, %%r10d\n\tsyscall"
                     : "=a"(r) : : "rdi", "rsi", "rdx", "r10", "rcx", "r11", "memory");
    if (r < 0) {
        volatile int *p = 0; *p = 1;
    }
    return 0;
}''', inc=L_STD, arch="x86_64")

T("antidbg.linux.ptrace_selfattach.v4", "antidbg.ptrace", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) {
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) != 0) _exit(1);
        waitpid(parent, NULL, 0);
        ptrace(PTRACE_CONT, parent, 0, 0);
        ptrace(PTRACE_DETACH, parent, 0, 0);
        _exit(0);
    }
    int st = 0;
    waitpid(child, &st, 0);
    if (WEXITSTATUS(st) != 0) { puts("being traced"); exit(2); }
    return 0;
}''', inc=L_STD + ("sys/ptrace.h", "sys/wait.h", "sys/types.h"))

T("antidbg.linux.ptrace_double.v5", "antidbg.ptrace", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int offset = 0;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == 0) offset = 2;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) offset *= 3;
    if (offset != 6) { fprintf(stderr, "nope\n"); exit(offset); }
    return offset;
}''', inc=L_STD + ("sys/ptrace.h",))

T("antidbg.linux.ptrace_dlsym.v6", "antidbg.ptrace", AD, "linux", r'''
typedef long (*@F_pt)(int, int, void *, void *);
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_pt fn = (@F_pt)dlsym(RTLD_DEFAULT, "ptrace");
    if (fn && fn(0, 0, 0, 0) < 0) return -1;
    return 0;
}''', inc=L_STD + ("dlfcn.h",))

T("antidbg.linux.ptrace_ctor.v7", "antidbg.ptrace", AD, "linux", r'''
static volatile int @F_flag;
__attribute__((constructor)) static void @F_ctor(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) { @F_flag = 1; _exit(127); }
}
__attribute__((noinline)) int @F(int argc, char **argv) { return @F_flag; }''',
  inc=L_STD + ("sys/ptrace.h",))

# ---------------------------------------------------------------- linux: TracerPid
T("antidbg.linux.tracerpid_fgets.v1", "antidbg.tracerpid", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            if (pid != 0) exit(1);
            return 0;
        }
    }
    fclose(f);
    return 0;
}''', inc=L_STD)

T("antidbg.linux.tracerpid_read.v2", "antidbg.tracerpid", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *p = strstr(buf, "TracerPid:");
    if (p && strtol(p + 10, NULL, 10) > 0) return 1;
    return 0;
}''', inc=L_STD + ("fcntl.h",))

T("antidbg.linux.tracerpid_stackpath.v3", "antidbg.tracerpid", (AD, "obfuscation"), "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile char path[18];
    path[0]='/'; path[1]='p'; path[2]='r'; path[3]='o'; path[4]='c'; path[5]='/';
    path[6]='s'; path[7]='e'; path[8]='l'; path[9]='f'; path[10]='/'; path[11]='s';
    path[12]='t'; path[13]='a'; path[14]='t'; path[15]='u'; path[16]='s'; path[17]=0;
    volatile char key[11];
    key[0]='T'; key[1]='r'; key[2]='a'; key[3]='c'; key[4]='e'; key[5]='r';
    key[6]='P'; key[7]='i'; key[8]='d'; key[9]=':'; key[10]=0;
    char line[200];
    FILE *f = fopen((const char *)path, "r");
    if (!f) return 0;
    int hit = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, (const char *)key, 10) && atoi(line + 10)) hit = 1;
    fclose(f);
    return hit;
}''', inc=L_STD)

T("antidbg.linux.tracerpid_sscanf.v4", "antidbg.tracerpid", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[128]; int tp = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "TracerPid:\t%d", &tp) == 1) break;
    fclose(f);
    if (tp) { kill(getpid(), SIGKILL); }
    return tp;
}''', inc=L_STD + ("signal.h",))

T("antidbg.linux.tracerpid_getline.v5", "antidbg.tracerpid", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)getpid());
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL; size_t cap = 0; int traced = 0;
    while (getline(&line, &cap, f) > 0) {
        if (!strncmp(line, "TracerPid:", 10)) { traced = strcmp(line, "TracerPid:\t0\n") != 0; break; }
    }
    free(line); fclose(f);
    if (traced) abort();
    return 0;
}''', inc=L_STD)

# ---------------------------------------------------------------- linux: parent process
T("antidbg.linux.parent_exe.v1", "antidbg.parent", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char p[64], exe[512];
    snprintf(p, sizeof p, "/proc/%d/exe", (int)getppid());
    ssize_t n = readlink(p, exe, sizeof exe - 1);
    if (n <= 0) return 0;
    exe[n] = 0;
    if (strstr(exe, "gdb") || strstr(exe, "lldb") || strstr(exe, "strace")) exit(1);
    return 0;
}''', inc=L_STD)

T("antidbg.linux.parent_cmdline.v2", "antidbg.parent", AD, "linux", r'''
static const char *@F_tools[] = {"gdb", "lldb", "strace", "ltrace", "radare2", "r2", "valgrind", "edb", "rr", 0};
__attribute__((noinline)) int @F(int argc, char **argv) {
    char p[64], cmd[256] = {0};
    snprintf(p, sizeof p, "/proc/%d/cmdline", (int)getppid());
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fread(cmd, 1, sizeof cmd - 1, f);
    fclose(f);
    const char *base = strrchr(cmd, '/'); base = base ? base + 1 : cmd;
    for (int i = 0; @F_tools[i]; i++)
        if (!strcmp(base, @F_tools[i])) return 1;
    return 0;
}''', inc=L_STD)

T("antidbg.linux.parent_comm.v3", "antidbg.parent", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char p[64], comm[64] = {0};
    sprintf(p, "/proc/%d/comm", getppid());
    FILE *f = fopen(p, "r");
    if (!f || !fgets(comm, sizeof comm, f)) { if (f) fclose(f); return 0; }
    fclose(f);
    comm[strcspn(comm, "\n")] = 0;
    if (!strcmp(comm, "gdb") || !strcmp(comm, "strace") || !strcmp(comm, "ltrace") || !strcmp(comm, "frida-server"))
        _exit(0);
    return 0;
}''', inc=L_STD)

T("antidbg.linux.parent_statppid.v4", "antidbg.parent", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    FILE *f = fopen("/proc/self/stat", "r");
    int pid, ppid; char comm[64], st;
    if (!f) return 0;
    if (fscanf(f, "%d %63s %c %d", &pid, comm, &st, &ppid) != 4) { fclose(f); return 0; }
    fclose(f);
    char path[64], name[128] = {0};
    snprintf(path, sizeof path, "/proc/%d/comm", ppid);
    f = fopen(path, "r");
    if (f) { fgets(name, sizeof name, f); fclose(f); }
    return strstr(name, "gdb") != NULL || strstr(name, "dbg") != NULL;
}''', inc=L_STD)

# ---------------------------------------------------------------- linux: env / instrumentation
T("antidbg.linux.env_ldpreload.v1", "antidbg.env", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (getenv("LD_PRELOAD") != NULL) { fputs("preload hooking detected\n", stderr); exit(1); }
    if (getenv("LD_AUDIT")) exit(1);
    return 0;
}''', inc=L_STD)

T("antidbg.linux.env_gdbvars.v2", "antidbg.env", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    /* gdb exports LINES and COLUMNS to the inferior */
    if (getenv("LINES") && getenv("COLUMNS")) return 1;
    const char *u = getenv("_");
    if (u && (strstr(u, "gdb") || strstr(u, "strace") || strstr(u, "ltrace"))) return 1;
    return 0;
}''', inc=L_STD)

T("antidbg.linux.env_environ.v3", "antidbg.env", AD, "linux", r'''
extern char **environ;
__attribute__((noinline)) int @F(int argc, char **argv) {
    for (char **e = environ; *e; e++) {
        if (!strncmp(*e, "LD_PRELOAD=", 11) || !strncmp(*e, "LD_DEBUG=", 9) || !strncmp(*e, "FRIDA", 5))
            return 1;
    }
    return 0;
}''', inc=L_STD)

T("antidbg.linux.env_unsetpreload.v4", "antidbg.env", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char *p = getenv("LD_PRELOAD");
    if (p) {
        unsetenv("LD_PRELOAD");
        execv("/proc/self/exe", argv);
    }
    return 0;
}''', inc=L_STD)

T("antidbg.linux.frida_maps.v1", "antidbg.instrumentation", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    int bad = 0;
    while (fgets(line, sizeof line, f))
        if (strstr(line, "frida") || strstr(line, "gum-js") || strstr(line, "libgadget")) bad = 1;
    fclose(f);
    return bad;
}''', inc=L_STD)

T("antidbg.linux.frida_threads.v2", "antidbg.instrumentation", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    DIR *d = opendir("/proc/self/task");
    struct dirent *e; char p[300], name[64]; int bad = 0;
    if (!d) return 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        if (fgets(name, sizeof name, f) && (strstr(name, "gum-js-loop") || strstr(name, "gmain") || strstr(name, "gdbus")))
            bad = 1;
        fclose(f);
    }
    closedir(d);
    return bad;
}''', inc=L_STD + ("dirent.h",))

T("antidbg.linux.frida_port.v3", "antidbg.instrumentation", (AD, "network"), "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(27042);
    inet_aton("127.0.0.1", &sa.sin_addr);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int r = connect(s, (struct sockaddr *)&sa, sizeof sa);
    close(s);
    return r == 0;
}''', inc=L_STD + ("sys/socket.h", "netinet/in.h", "arpa/inet.h"))

T("antidbg.linux.hook_prologue.v4", "antidbg.instrumentation", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *names[] = {"open", "read", "connect", "ptrace", "strcmp"};
    for (int i = 0; i < 5; i++) {
        unsigned char *p = (unsigned char *)dlsym(RTLD_DEFAULT, names[i]);
        if (!p) continue;
        if (p[0] == 0xCC || p[0] == 0xE9 || (p[0] == 0xFF && p[1] == 0x25)) return 1;
    }
    return 0;
}''', inc=L_STD + ("dlfcn.h",))

# ---------------------------------------------------------------- linux: SIGTRAP / prevention
T("antidbg.linux.sigtrap_raise.v1", "antidbg.trap", AD, "linux", r'''
static volatile int @F_seen;
static void @F_h(int s) { @F_seen = 1; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    signal(SIGTRAP, @F_h);
    raise(SIGTRAP);
    if (!@F_seen) { puts("debugger swallowed SIGTRAP"); exit(1); }
    return 0;
}''', inc=L_STD + ("signal.h",))

T("antidbg.linux.sigtrap_int3.v2", "antidbg.trap", AD, "linux", r'''
static volatile sig_atomic_t @F_hit;
static void @F_h(int s, siginfo_t *i, void *c) { @F_hit++; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = @F_h; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sa, NULL);
    __asm__ volatile("int3");
    return @F_hit ? 0 : 1;
}''', inc=L_STD + ("signal.h",))

T("antidbg.linux.sigtrap_kill.v3", "antidbg.trap", AD, "linux", r'''
static volatile int @F_n;
static void @F_h(int s) { @F_n += 7; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = @F_h;
    sigaction(SIGTRAP, &sa, 0);
    kill(getpid(), SIGTRAP);
    if (@F_n != 7) _exit(9);
    return 0;
}''', inc=L_STD + ("signal.h",))

T("antidbg.linux.prctl_dumpable.v4", "antidbg.trap", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    /* block ptrace attach + core dumps */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
    return prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
}''', inc=L_STD + ("sys/prctl.h", "sys/resource.h"))

T("antidbg.linux.int3_icebp.v5", "antidbg.trap", AD, "linux", r'''
static sigjmp_buf @F_jb;
static void @F_h(int s) { siglongjmp(@F_jb, 1); }
__attribute__((noinline)) int @F(int argc, char **argv) {
    signal(SIGTRAP, @F_h);
    if (sigsetjmp(@F_jb, 1) == 0) {
        __asm__ volatile(".byte 0xf1");
        return 1; /* debugger ate it */
    }
    return 0;
}''', inc=L_STD + ("signal.h", "setjmp.h"))

# ---------------------------------------------------------------- any: timing
T("antidbg.any.rdtsc_asm.v1", "antidbg.timing", AD, "any", r'''
static unsigned long long @F_tsc(void) {
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned long long a = @F_tsc();
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    unsigned long long b = @F_tsc();
    if (b - a > 0x100000ULL) exit(1);
    return x & 1;
}''', inc=("stdlib.h",))

T("antidbg.any.rdtsc_intrin.v2", "antidbg.timing", AD, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned long long t0 = __rdtsc();
    volatile unsigned s = 0;
    for (unsigned i = 0; i < 1000; i++) s ^= i * 2654435761u;
    unsigned long long d = __rdtsc() - t0;
    return d > 5000000ULL ? 1 : 0;
}''', inc=("x86intrin.h",))

T("antidbg.linux.clock_delta.v3", "antidbg.timing", AD, "linux", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    volatile long acc = 0;
    for (long i = 0; i < 20000; i++) acc += i ^ (i >> 3);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    if (ms > 200) { fprintf(stderr, "too slow, stepping?\n"); _exit(4); }
    return (int)(acc & 1);
}''', inc=L_STD + ("time.h",))

T("antidbg.win.qpc_delta.v4", "antidbg.timing", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    volatile int x = 0;
    for (int i = 0; i < 5000; i++) x += i;
    QueryPerformanceCounter(&b);
    double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart;
    if (ms > 100.0) ExitProcess(1);
    return x & 1;
}''', inc=("windows.h",))

T("antidbg.win.gettickcount_delta.v5", "antidbg.timing", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    DWORD t = GetTickCount();
    volatile unsigned v = 1;
    for (int i = 0; i < 100000; i++) v = v * 3 + 1;
    if (GetTickCount() - t > 1000) { TerminateProcess(GetCurrentProcess(), 0); }
    return (int)(v & 1);
}''', inc=("windows.h",))

T("antidbg.any.time_delta.v6", "antidbg.timing", AD, "any", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    time_t a = time(NULL);
    volatile double d = 1.0;
    for (int i = 1; i < 2000; i++) d = d * 1.0000001 + 1.0 / i;
    if (time(NULL) - a > 2) exit(5);
    return d > 0;
}''', inc=("stdlib.h", "time.h"))

# ---------------------------------------------------------------- any/linux/windows: breakpoint & integrity
T("antidbg.any.bpscan_self.v1", "antidbg.bpscan", AD, "any", r'''
static __attribute__((noinline)) int @F_target(int x) { return x * 31 + 7; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    const unsigned char *p = (const unsigned char *)(void *)&@F_target;
    for (int i = 0; i < 48; i++)
        if (p[i] == 0xCC) return 1;
    return @F_target(argc) == 0;
}''')

T("antidbg.any.code_checksum.v2", "antidbg.bpscan", AD, "any", r'''
static volatile unsigned @F_expect = 0x5a3c91u;
static __attribute__((noinline)) int @F_a(int v) { return v ^ 0x55; }
static __attribute__((noinline)) int @F_b(int v) { return v + 3; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    const unsigned char *s = (const unsigned char *)(void *)&@F_a;
    unsigned h = 0;
    for (int i = 0; i < 64; i++) h = (h << 5) + h + s[i];
    if (h != @F_expect && @F_expect != 0x5a3c91u) exit(1); /* integrity */
    return (h == 0) + @F_a(argc) + @F_b(argc) - (@F_a(argc) + @F_b(argc));
}''', inc=("stdlib.h",))

T("antidbg.any.bpscan_loop.v3", "antidbg.bpscan", AD, "any", r'''
static __attribute__((noinline)) unsigned @F_work(unsigned x) { return x * 2654435761u >> 7; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile unsigned char *p = (volatile unsigned char *)(void *)&@F_work;
    unsigned cnt = 0;
    for (unsigned i = 0; i < 128; i++) {
        unsigned char op = p[i] ^ 0x55u;
        if (op == (0xCC ^ 0x55u)) cnt++;
    }
    return cnt > 0 ? -1 : (int)(@F_work(argc) & 1);
}''')

T("antidbg.win.hwbp_context.v4", "antidbg.bpscan", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    CONTEXT ctx; memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 0;
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ExitProcess(0);
    return 0;
}''', inc=("windows.h", "string.h"))

T("antidbg.win.hook_check.v5", "antidbg.bpscan", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HMODULE k = GetModuleHandleA("kernel32.dll");
    const char *fns[] = {"IsDebuggerPresent", "CreateFileW", "ReadProcessMemory", "GetProcAddress"};
    for (int i = 0; i < 4; i++) {
        unsigned char *p = (unsigned char *)GetProcAddress(k, fns[i]);
        if (p && (p[0] == 0xCC || p[0] == 0xE9 || p[0] == 0xEB)) return 1;
    }
    return 0;
}''', inc=("windows.h",))

# ---------------------------------------------------------------- windows: API checks
T("antidbg.win.isdebuggerpresent.v1", "antidbg.win_api", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (IsDebuggerPresent()) { MessageBoxA(NULL, "Debugger", "Error", 0); ExitProcess(1); }
    return 0;
}''', inc=("windows.h",), libs=("user32",))

T("antidbg.win.checkremote.v2", "antidbg.win_api", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present ? 1 : 0;
}''', inc=("windows.h",))

T("antidbg.win.outputdebugstring.v3", "antidbg.win_api", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    SetLastError(0x1234);
    OutputDebugStringA("%s%s%s%s%s%s%s");
    if (GetLastError() == 0x1234) return 0;
    return 1;
}''', inc=("windows.h",))

T("antidbg.win.closehandle_invalid.v4", "antidbg.win_api", AD, "windows", r'''
static volatile LONG @F_exc;
static LONG CALLBACK @F_veh(PEXCEPTION_POINTERS e) {
    if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INVALID_HANDLE) { @F_exc = 1; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    CloseHandle((HANDLE)(ULONG_PTR)0xDEADBEEF);
    RemoveVectoredExceptionHandler(h);
    return @F_exc;
}''', inc=("windows.h",))

T("antidbg.win.hidethread.v5", "antidbg.win_api", AD, "windows", r'''
typedef LONG (WINAPI *@F_nsit)(HANDLE, ULONG, PVOID, ULONG);
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_nsit f = (@F_nsit)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (f) f(GetCurrentThread(), 0x11 /* ThreadHideFromDebugger */, NULL, 0);
    return f != NULL;
}''', inc=("windows.h",))

T("antidbg.win.debugactiveself.v6", "antidbg.win_api", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    /* a process cannot be debugged twice: spawn self as debugger-guard child */
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    if (argc > 1 && !strcmp(argv[1], "--guard")) {
        DWORD pid = (DWORD)atoi(argv[2]);
        if (!DebugActiveProcess(pid)) return 1;
        DEBUG_EVENT ev;
        while (WaitForDebugEvent(&ev, INFINITE)) ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
    return 0;
}''', inc=("windows.h", "stdlib.h", "string.h"))

# ---------------------------------------------------------------- windows: NtQueryInformationProcess
_NTQIP_TD = r'''typedef LONG (WINAPI *@F_ntqip)(HANDLE, ULONG, PVOID, ULONG, PULONG);'''
T("antidbg.win.ntqip_debugport.v1", "antidbg.win_ntqip", AD, "windows", _NTQIP_TD + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_ntqip q = (@F_ntqip)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    DWORD_PTR port = 0;
    if (q && q(GetCurrentProcess(), 7 /* ProcessDebugPort */, &port, sizeof port, NULL) == 0 && port) return 1;
    return 0;
}''', inc=("windows.h",))

T("antidbg.win.ntqip_debugflags.v2", "antidbg.win_ntqip", AD, "windows", _NTQIP_TD + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HMODULE nt = LoadLibraryA("ntdll.dll");
    @F_ntqip q = (@F_ntqip)GetProcAddress(nt, "NtQueryInformationProcess");
    ULONG noDebugInherit = 1;
    if (q) q((HANDLE)-1, 0x1F /* ProcessDebugFlags */, &noDebugInherit, sizeof noDebugInherit, NULL);
    if (noDebugInherit == 0) ExitProcess(2);
    return 0;
}''', inc=("windows.h",))

T("antidbg.win.ntqip_debugobject.v3", "antidbg.win_ntqip", AD, "windows", _NTQIP_TD + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_ntqip q = (@F_ntqip)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    HANDLE dbgObj = NULL;
    LONG st = q ? q(GetCurrentProcess(), 0x1E /* ProcessDebugObjectHandle */, &dbgObj, sizeof dbgObj, NULL) : -1;
    return (st == 0 && dbgObj != NULL);
}''', inc=("windows.h",))

T("antidbg.win.ntqip_linked.v4", "antidbg.win_ntqip", AD, "windows", r'''
__declspec(dllimport) LONG NTAPI NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
__attribute__((noinline)) int @F(int argc, char **argv) {
    DWORD_PTR port = 0; ULONG flags = 1; HANDLE obj = 0;
    NtQueryInformationProcess(GetCurrentProcess(), 7, &port, sizeof port, NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &flags, sizeof flags, NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &obj, sizeof obj, NULL);
    return (port != 0) | (flags == 0) | (obj != 0);
}''', inc=("windows.h",), libs=("ntdll",))

T("antidbg.win.ntqsi_kerneldbg.v5", "antidbg.win_ntqip", AD, "windows", r'''
typedef LONG (WINAPI *@F_ntqsi)(ULONG, PVOID, ULONG, PULONG);
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } info = {0, 1};
    @F_ntqsi q = (@F_ntqsi)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (q && q(0x23 /* SystemKernelDebuggerInformation */, &info, sizeof info, NULL) == 0)
        if (info.DebuggerEnabled && !info.DebuggerNotPresent) return 1;
    return 0;
}''', inc=("windows.h",))

# ---------------------------------------------------------------- windows: PEB
T("antidbg.win.peb_gs_intrin.v1", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (peb[2]) ExitProcess(0);
    return 0;
}''', inc=("windows.h", "intrin.h"), arch="x86_64")

T("antidbg.win.peb_fs_intrin.v2", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb = (unsigned char *)__readfsdword(0x30);
    return peb[2] != 0;
}''', inc=("windows.h", "intrin.h"), arch="x86")

T("antidbg.win.peb_ntglobalflag64.v3", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    DWORD flags = *(DWORD *)(peb + 0xBC);
    if (flags & 0x70) return 1;   /* FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS */
    return 0;
}''', inc=("windows.h", "intrin.h"), arch="x86_64")

T("antidbg.win.peb_ntglobalflag32.v4", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb = (unsigned char *)__readfsdword(0x30);
    if (*(DWORD *)(peb + 0x68) & 0x70) ExitProcess(3);
    return 0;
}''', inc=("windows.h", "intrin.h"), arch="x86")

T("antidbg.win.peb_asm64.v5", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb[2];
}''', inc=("windows.h",), arch="x86_64")

T("antidbg.win.peb_asm32.v6", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
    if (peb[2]) { volatile int *z = 0; *z = 0; }
    return 0;
}''', inc=("windows.h",), arch="x86")

T("antidbg.win.peb_heapflags64.v7", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    unsigned char *heap = *(unsigned char **)(peb + 0x30);
    DWORD flags = *(DWORD *)(heap + 0x70), force = *(DWORD *)(heap + 0x74);
    return (flags & ~HEAP_GROWABLE) != 0 || force != 0;
}''', inc=("windows.h", "intrin.h"), arch="x86_64")

T("antidbg.win.peb_teb.v8", "antidbg.win_peb", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (peb->BeingDebugged) return 1;
    return 0;
}''', inc=("windows.h", "winternl.h"))

# ---------------------------------------------------------------- windows: exception tricks
_VEH_HDR = r'''
static volatile LONG @F_caught;
static LONG CALLBACK @F_veh(PEXCEPTION_POINTERS e) {
    @F_caught = 1;
#ifdef _WIN64
    e->ContextRecord->Rip += @F_SKIP;
#else
    e->ContextRecord->Eip += @F_SKIP;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}'''
T("antidbg.win.int2d.v1", "antidbg.win_exc", AD, "windows", "#define @F_SKIP 1" + _VEH_HDR + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    __asm__ volatile("int $0x2d\n\tnop");
    RemoveVectoredExceptionHandler(h);
    return @F_caught ? 0 : 1;   /* debugger swallowed the exception */
}''', inc=("windows.h",))

T("antidbg.win.int3_veh.v2", "antidbg.win_exc", AD, "windows", "#define @F_SKIP 0" + _VEH_HDR + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    __asm__ volatile("int3");
    RemoveVectoredExceptionHandler(h);
    if (!@F_caught) ExitProcess(1);
    return 0;
}''', inc=("windows.h",))

T("antidbg.win.unhandled_filter.v3", "antidbg.win_exc", AD, "windows", r'''
static volatile int @F_ok;
static LONG WINAPI @F_filter(PEXCEPTION_POINTERS e) { @F_ok = 1; return EXCEPTION_CONTINUE_EXECUTION; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    SetUnhandledExceptionFilter(@F_filter);
    RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    return @F_ok ? 0 : 1;
}''', inc=("windows.h",))

T("antidbg.win.dbg_ctrl_c.v4", "antidbg.win_exc", AD, "windows", "#define @F_SKIP 0" + _VEH_HDR + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    RaiseException(DBG_CONTROL_C, 0, 0, NULL);
    RaiseException(0x40010006 /* DBG_PRINTEXCEPTION_C */, 0, 0, NULL);
    RemoveVectoredExceptionHandler(h);
    return !@F_caught;
}''', inc=("windows.h",))

T("antidbg.win.icebp.v5", "antidbg.win_exc", AD, "windows", "#define @F_SKIP 0" + _VEH_HDR + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
    __asm__ volatile(".byte 0xf1");
    RemoveVectoredExceptionHandler(h);
    return @F_caught == 0;
}''', inc=("windows.h",))

T("antidbg.win.trapflag.v6", "antidbg.win_exc", AD, "windows", "#define @F_SKIP 0" + _VEH_HDR + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PVOID h = AddVectoredExceptionHandler(1, @F_veh);
#ifdef _WIN64
    __asm__ volatile("pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\tnop" ::: "memory");
#else
    __asm__ volatile("pushfl\n\torl $0x100, (%%esp)\n\tpopfl\n\tnop" ::: "memory");
#endif
    RemoveVectoredExceptionHandler(h);
    return !@F_caught;
}''', inc=("windows.h",))

# ---------------------------------------------------------------- windows: debugger processes / windows
T("antidbg.win.toolhelp_names.v1", "antidbg.win_procs", AD, "windows", r'''
static const char *@F_dbg[] = {"ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
    "windbg.exe", "immunitydebugger.exe", "processhacker.exe", "procmon.exe", "wireshark.exe",
    "fiddler.exe", "dnspy.exe", "cheatengine-x86_64.exe", 0};
__attribute__((noinline)) int @F(int argc, char **argv) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof pe;
    int found = 0;
    if (Process32First(s, &pe)) do {
        for (int i = 0; @F_dbg[i]; i++) if (!lstrcmpiA(pe.szExeFile, @F_dbg[i])) found = 1;
    } while (Process32Next(s, &pe));
    CloseHandle(s);
    return found;
}''', inc=("windows.h", "tlhelp32.h"))

T("antidbg.win.findwindow.v2", "antidbg.win_procs", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *cls[] = {"OLLYDBG", "WinDbgFrameClass", "ID", "Zeta Debugger", "Rock Debugger", "ObsidianGUI", "Qt5QWindowIcon"};
    for (int i = 0; i < 7; i++) if (FindWindowA(cls[i], NULL)) return 1;
    if (FindWindowA(NULL, "x64dbg")) return 1;
    return 0;
}''', inc=("windows.h",), libs=("user32",))

T("antidbg.win.parent_explorer.v3", "antidbg.win_procs", AD, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    DWORD me = GetCurrentProcessId(), parent = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof pe;
    if (Process32First(s, &pe)) do { if (pe.th32ProcessID == me) parent = pe.th32ParentProcessID; } while (Process32Next(s, &pe));
    int bad = 1;
    if (Process32First(s, &pe)) do {
        if (pe.th32ProcessID == parent && (!lstrcmpiA(pe.szExeFile, "explorer.exe") || !lstrcmpiA(pe.szExeFile, "cmd.exe"))) bad = 0;
    } while (Process32Next(s, &pe));
    CloseHandle(s);
    return bad;
}''', inc=("windows.h", "tlhelp32.h"))

T("antidbg.win.enumwindows_title.v4", "antidbg.win_procs", AD, "windows", r'''
static volatile int @F_hit;
static BOOL CALLBACK @F_cb(HWND w, LPARAM l) {
    char t[256];
    if (GetWindowTextA(w, t, sizeof t) > 0 && (strstr(t, "x64dbg") || strstr(t, "IDA -") || strstr(t, "Cheat Engine") || strstr(t, "OllyDbg") || strstr(t, "Process Hacker")))
        @F_hit = 1;
    return TRUE;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    EnumWindows(@F_cb, 0);
    return @F_hit;
}''', inc=("windows.h", "string.h"), libs=("user32",))

T("antidbg.win.csrss_open.v5", "antidbg.win_procs", AD, "windows", r'''
typedef DWORD (WINAPI *@F_csr)(void);
__attribute__((noinline)) int @F(int argc, char **argv) {
    @F_csr f = (@F_csr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "CsrGetProcessId");
    if (!f) return 0;
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, f());
    if (h) { CloseHandle(h); return 1; } /* SeDebugPrivilege granted -> debugger */
    return 0;
}''', inc=("windows.h",))
