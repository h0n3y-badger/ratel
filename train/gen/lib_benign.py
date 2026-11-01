"""Benign filler and hard negatives.

Fillers give every sample ordinary program logic, so the model cannot tell a
technique apart by program size, toolchain or "looks synthetic". Hard
negatives are benign code that *resembles* a technique (CPU feature probing,
debugger-style ptrace, system-info printers, embedded high-entropy tables,
plugin loaders, timing for benchmarks, CRC/base64, help text naming VMs).
They are all labeled 0 for every capability.
"""
from common import B, H, c_bytes, c_str

STD = ("stdio.h", "stdlib.h", "string.h")
NAMES = ["alpha", "beta", "gamma", "delta", "config", "record", "entry", "node", "item", "token", "frame",
         "packet", "sample", "widget", "buffer", "vertex", "layer", "chunk", "cell", "slot"]


def _n(r):
    return r.choice(NAMES)


# ------------------------------------------------------------------ sorting
def _sort(r):
    algo = r.choice(["insertion", "shell", "qsort", "bubble"])
    n = r.randint(8, 64)
    vals = ",".join(str(r.randint(-1000, 1000)) for _ in range(n))
    body = {
        "insertion": "for (int i = 1; i < n; i++) { int k = a[i], j = i - 1; while (j >= 0 && a[j] > k) { a[j + 1] = a[j]; j--; } a[j + 1] = k; }",
        "shell": "for (int g = n / 2; g > 0; g /= 2) for (int i = g; i < n; i++) { int t = a[i], j; for (j = i; j >= g && a[j - g] > t; j -= g) a[j] = a[j - g]; a[j] = t; }",
        "qsort": "qsort(a, n, sizeof a[0], @F_cmp);",
        "bubble": "for (int i = 0; i < n; i++) for (int j = 0; j + 1 < n - i; j++) if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }",
    }[algo]
    return r'''
static int @F_cmp(const void *x, const void *y) { return *(const int *)x - *(const int *)y; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    int a[] = {%s}; int n = (int)(sizeof a / sizeof a[0]);
    (void)@F_cmp;
    %s
    long s = 0; for (int i = 0; i < n; i++) s = s * 31 + a[i];
    printf("%s sorted: %%d..%%d (%%ld)\n", a[0], a[n - 1], s);
    return (int)(s & 0x7f);
}''' % (vals, body, algo)


# ------------------------------------------------------------------ strings
def _strings(r):
    words = " ".join(r.choice(NAMES) for _ in range(r.randint(4, 12)))
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char line[256]; strncpy(line, argc > 1 ? argv[1] : %s, sizeof line - 1); line[sizeof line - 1] = 0;
    int words = 0, upper = 0; char *save = 0;
    for (char *t = strtok_r(line, " ,;", &save); t; t = strtok_r(0, " ,;", &save)) {
        words++;
        for (char *c = t; *c; c++) if (*c >= 'a' && *c <= 'z') { *c -= 32; upper++; }
        printf("[%%s] ", t);
    }
    printf("\n%%d words, %%d letters\n", words, upper);
    return words;
}''' % c_str(words)


def _strings_win(r):
    # strtok_r is missing on mingw: use strtok.
    return _strings(r).replace("strtok_r(line, \" ,;\", &save)", "strtok(line, \" ,;\")").replace("strtok_r(0, \" ,;\", &save)", "strtok(0, \" ,;\")")


def _ini(r):
    sec = _n(r)
    keys = [_n(r) + str(i) for i in range(r.randint(3, 8))]
    text = "\\n".join([f"[{sec}]"] + [f"{k} = {r.randint(0, 9999)}" for k in keys] + ["# comment", "name = example"])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *src = "%s";
    char key[64], val[64], section[64] = ""; int n = 0;
    const char *p = src;
    while (*p) {
        const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e - p) : strlen(p);
        char ln[128]; if (len >= sizeof ln) len = sizeof ln - 1; memcpy(ln, p, len); ln[len] = 0;
        if (ln[0] == '[') sscanf(ln, "[%%63[^]]]", section);
        else if (ln[0] != '#' && sscanf(ln, "%%63s = %%63s", key, val) == 2) { printf("%%s.%%s=%%s\n", section, key, val); n++; }
        p = e ? e + 1 : p + len;
    }
    return n;
}''' % text


def _csv(r):
    rows = "\\n".join(",".join(str(r.randint(0, 500)) for _ in range(4)) for _ in range(r.randint(3, 9)))
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *csv = "%s";
    double col[4] = {0}; int rows = 0, c = 0; const char *p = csv;
    while (*p) {
        col[c] += atof(p);
        while (*p && *p != ',' && *p != '\n') p++;
        if (*p == ',') c++; else if (*p == '\n') { c = 0; rows++; }
        if (*p) p++;
    }
    for (int i = 0; i < 4; i++) printf("col%%d avg %%.2f\n", i, rows ? col[i] / rows : 0.0);
    return rows;
}''' % rows


def _json(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *js = argc > 1 ? argv[1] : "{\"%s\": [1, 2, {\"x\": true}], \"n\": %d}";
    int depth = 0, maxd = 0, strs = 0, nums = 0; int in_str = 0;
    for (const char *p = js; *p; p++) {
        if (in_str) { if (*p == '\\' && p[1]) p++; else if (*p == '"') in_str = 0; continue; }
        if (*p == '"') { in_str = 1; strs++; }
        else if (*p == '{' || *p == '[') { if (++depth > maxd) maxd = depth; }
        else if (*p == '}' || *p == ']') depth--;
        else if (*p >= '0' && *p <= '9') { nums++; while (p[1] >= '0' && p[1] <= '9') p++; }
    }
    printf("depth %%d strings %%d numbers %%d\n", maxd, strs, nums);
    return depth == 0;
}''' % (_n(r), r.randint(1, 999))


# ------------------------------------------------------------------ math
def _matrix(r):
    n = r.choice([3, 4, 6, 8])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    double a[%d][%d], b[%d][%d], c[%d][%d];
    for (int i = 0; i < %d; i++) for (int j = 0; j < %d; j++) { a[i][j] = i + j * %d.5; b[i][j] = (i == j) ? 2.0 : 0.25; }
    for (int i = 0; i < %d; i++) for (int j = 0; j < %d; j++) { double s = 0; for (int k = 0; k < %d; k++) s += a[i][k] * b[k][j]; c[i][j] = s; }
    double tr = 0; for (int i = 0; i < %d; i++) tr += c[i][i];
    printf("trace %%.3f\n", tr);
    return (int)tr;
}''' % ((n,) * 8 + (r.randint(1, 9),) + (n,) * 4)


def _primes(r):
    lim = r.choice([1000, 5000, 20000, 65536])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    static unsigned char sieve[%d + 1]; int count = 0;
    for (int i = 2; i <= %d; i++) {
        if (sieve[i]) continue; count++;
        for (long j = (long)i * i; j <= %d; j += i) sieve[j] = 1;
    }
    printf("%%d primes below %d\n", count);
    return count;
}''' % (lim, lim, lim, lim)


def _stats(r):
    n = r.randint(10, 40)
    vals = ",".join(f"{r.uniform(-50, 50):.3f}" for _ in range(n))
    return r'''
#include <math.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    double v[] = {%s}; int n = (int)(sizeof v / sizeof v[0]);
    double m = 0, s2 = 0, mn = v[0], mx = v[0];
    for (int i = 0; i < n; i++) { m += v[i]; if (v[i] < mn) mn = v[i]; if (v[i] > mx) mx = v[i]; }
    m /= n; for (int i = 0; i < n; i++) s2 += (v[i] - m) * (v[i] - m);
    printf("mean %%.3f sd %%.3f range [%%.2f, %%.2f]\n", m, sqrt(s2 / n), mn, mx);
    return (int)m;
}''' % vals


def _fixed(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int x = (argc + %d) << 16, acc = 0;
    for (int i = 0; i < %d; i++) { x = (int)(((long long)x * %d) >> 16) + (1 << 12); acc ^= x >> 8; }
    printf("fixed %%d %%d\n", x >> 16, acc);
    return acc & 0xff;
}''' % (r.randint(1, 50), r.randint(10, 200), r.randint(40000, 70000))


# ------------------------------------------------------------------ data structures
def _list(r):
    return r'''
struct @F_node { int v; struct @F_node *next; };
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct @F_node *head = 0;
    for (int i = 0; i < %d; i++) { struct @F_node *n = malloc(sizeof *n); n->v = i * %d %% 97; n->next = head; head = n; }
    struct @F_node *prev = 0; while (head) { struct @F_node *nx = head->next; head->next = prev; prev = head; head = nx; }
    int s = 0; while (prev) { struct @F_node *nx = prev->next; s += prev->v; free(prev); prev = nx; }
    printf("list sum %%d\n", s);
    return s;
}''' % (r.randint(5, 100), r.randint(3, 50))


def _hashtable(r):
    # djb2 / FNV are common in benign hash tables (and in API hashing): hard-ish negative.
    h = r.choice([("5381", "h * 33 + c"), ("2166136261u", "(h ^ c) * 16777619u"), ("0", "h * 131 + c")])
    keys = ",".join(c_str(_n(r) + str(i)) for i in range(r.randint(4, 12)))
    return r'''
struct @F_ent { const char *k; int v; int used; };
static unsigned @F_hash(const char *s) { unsigned h = %s; for (; *s; s++) { unsigned c = (unsigned char)*s; h = %s; } return h; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    static struct @F_ent tab[64]; const char *keys[] = {%s}; int n = (int)(sizeof keys / sizeof keys[0]);
    for (int i = 0; i < n; i++) { unsigned b = @F_hash(keys[i]) & 63; while (tab[b].used) b = (b + 1) & 63; tab[b].k = keys[i]; tab[b].v = i; tab[b].used = 1; }
    int found = 0; for (int i = 0; i < n; i++) { unsigned b = @F_hash(keys[i]) & 63; while (tab[b].used && strcmp(tab[b].k, keys[i])) b = (b + 1) & 63; found += tab[b].used; }
    printf("%%d/%%d keys\n", found, n);
    return found;
}''' % (h[0], h[1], keys)


def _ringbuf(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int rb[%d]; int head = 0, tail = 0, cnt = 0, out = 0;
    for (int i = 0; i < %d; i++) {
        if (cnt == %d) { out += rb[tail]; tail = (tail + 1) %% %d; cnt--; }
        rb[head] = i * i; head = (head + 1) %% %d; cnt++;
    }
    printf("ring %%d %%d\n", cnt, out);
    return out & 0xff;
}''' % (lambda k, it: (k, it, k, k, k))(r.choice([4, 8, 16, 32]), r.randint(20, 300))


# ------------------------------------------------------------------ I/O, CLI, env
def _fileio(r):
    fn = r.choice(["app.log", "settings.cfg", "output.txt", "cache.idx", "state.json"])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    FILE *f = fopen(argc > 2 ? argv[2] : "%s", "a+");
    if (!f) { perror("open"); return 1; }
    fprintf(f, "run argc=%%d name=%%s\n", argc, argv[0]);
    fseek(f, 0, SEEK_SET); char ln[200]; int lines = 0;
    while (fgets(ln, sizeof ln, f)) lines++;
    fclose(f);
    printf("%%d lines in log\n", lines);
    return lines;
}''' % fn


def _cli(r):
    opts = r.sample(["verbose", "quiet", "output", "input", "level", "force", "dry-run", "color", "threads", "help"], 4)
    cases = "\n".join(f'        else if (!strcmp(a, "--{o}")) flags |= {1 << i};' for i, o in enumerate(opts))
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int flags = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h")) { printf("usage: %%s [--%s] [--%s] [--%s] [--%s]\n", argv[0]); return 0; }
%s
        else fprintf(stderr, "unknown option %%s\n", a);
    }
    return flags;
}''' % (opts[0], opts[1], opts[2], opts[3], cases)


def _env(r):
    var = r.choice(["HOME", "USER", "LANG", "PATH", "TERM", "XDG_CONFIG_HOME", "TMPDIR", "EDITOR"])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *v = getenv("%s");
    char path[512]; snprintf(path, sizeof path, "%%s/.%src", v ? v : ".");
    printf("config: %%s\n", path);
    return v ? (int)strlen(v) : 0;
}''' % (var, _n(r))


def _time(r):
    fmt = r.choice(["%Y-%m-%d %H:%M:%S", "%a %b %d %Y", "%H:%M", "%Y%m%dT%H%M%SZ"])
    return r'''
#include <time.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    time_t now = time(NULL); struct tm *t = localtime(&now); char buf[64];
    strftime(buf, sizeof buf, "%s", t);
    printf("[%%s] started\n", buf);
    return t->tm_hour;
}''' % fmt


def _lexer(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "x = %d + y * (z - %d) / 2";
    enum { S_START, S_ID, S_NUM } st = S_START; int ids = 0, nums = 0, ops = 0;
    for (const char *p = src;; p++) {
        char c = *p;
        int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        int digit = c >= '0' && c <= '9';
        switch (st) {
        case S_ID: if (alpha || digit) continue; ids++; st = S_START; break;
        case S_NUM: if (digit) continue; nums++; st = S_START; break;
        default: break;
        }
        if (!c) break;
        if (alpha) st = S_ID; else if (digit) st = S_NUM; else if (c != ' ') ops++;
    }
    printf("ids %%d nums %%d ops %%d\n", ids, nums, ops);
    return ids + nums + ops;
}''' % (r.randint(1, 99), r.randint(1, 99))


def _rle(r):
    # Non-crypto compression.
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char in[256], out[512]; int n = 0, o = 0;
    for (int i = 0; i < 256; i++) in[i] = (unsigned char)((i / %d) * %d);
    while (n < 256) { int run = 1; while (n + run < 256 && in[n + run] == in[n] && run < 255) run++; out[o++] = (unsigned char)run; out[o++] = in[n]; n += run; }
    printf("rle 256 -> %%d bytes\n", o);
    return o;
}''' % (r.randint(2, 32), r.randint(1, 7))


def _lz(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *s = argc > 1 ? argv[1] : "%s";
    int n = (int)strlen(s), i = 0, tokens = 0;
    while (i < n) {
        int best = 0, bo = 0;
        for (int j = (i > 255 ? i - 255 : 0); j < i; j++) { int k = 0; while (i + k < n && s[j + k] == s[i + k] && k < 15) k++; if (k > best) { best = k; bo = i - j; } }
        if (best >= 3) { i += best; } else i++;
        tokens++; (void)bo;
    }
    printf("lz: %%d tokens for %%d bytes\n", tokens, n);
    return tokens;
}''' % " ".join(r.choice(NAMES) for _ in range(r.randint(6, 20)))


def _bits(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned v = (unsigned)argc * %du, pc = 0, rev = 0;
    for (unsigned x = v; x; x &= x - 1) pc++;
    for (int i = 0; i < 32; i++) rev |= ((v >> i) & 1u) << (31 - i);
    printf("popcount %%u reversed %%08x\n", pc, rev);
    return (int)pc;
}''' % r.randint(1000, 2 ** 31)


def _state_machine(r):
    states = ["@F_" + x for x in r.sample(["IDLE", "CONNECTING", "READY", "BUSY", "ERROR", "DONE", "WAIT", "RETRY"], 5)]
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    enum { %s } s = %s; int steps = 0;
    const char *ev = argc > 1 ? argv[1] : "abcabd";
    for (const char *e = ev; *e; e++, steps++) {
        switch (s) {
        case %s: s = *e == 'a' ? %s : %s; break;
        case %s: s = *e == 'b' ? %s : %s; break;
        case %s: s = *e == 'c' ? %s : %s; break;
        default: s = %s; break;
        }
    }
    printf("final state %%d after %%d events\n", (int)s, steps);
    return (int)s;
}''' % (", ".join(states), states[0], states[0], states[1], states[4], states[1], states[2], states[4],
        states[2], states[3], states[0], states[0])


def _bigtable(r):
    # Large low-entropy lookup table (normal data).
    n = r.choice([256, 1024, 4096])
    tab = bytes((i * 7 + (i >> 3)) & 0xff for i in range(n))
    return r'''
static const unsigned char @F_tab[%d] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned s = 0; for (int i = 0; i < %d; i += argc) s += @F_tab[i];
    printf("table checksum %%u\n", s);
    return (int)(s & 0xff);
}''' % (n, c_bytes(tab), n)


def _messages(r):
    msgs = [f"{_n(r)} {w}" for w in r.sample(["not found", "loaded", "saved", "failed to parse", "is deprecated",
                                              "out of range", "connected to database", "ready", "updated"], 5)]
    return r'''
static const char *@F_msgs[] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    int i = argc %% %d; fprintf(stderr, "warning: %%s\n", @F_msgs[i]);
    return i;
}''' % (",".join(c_str(m) for m in msgs), len(msgs))


for i, fn in enumerate([_sort, _ini, _csv, _json, _matrix, _primes, _stats, _fixed, _list, _hashtable,
                        _ringbuf, _fileio, _cli, _env, _time, _lexer, _rle, _lz, _bits, _state_machine,
                        _bigtable, _messages]):
    B(f"{fn.__name__.strip('_')}.v1", "any", fn, inc=STD)
B("strings.linux.v1", "linux", _strings, inc=STD)
B("strings.win.v1", "windows", _strings_win, inc=STD)


# ================================================================== hard negatives
def _hn_cpu_features(r):
    # CPUID for SIMD feature detection (leaf 1 / 7), NOT the hypervisor bit or leaf 0x40000000.
    return r'''
#include <cpuid.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned a, b, c, d; int simd = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) { if (d & (1u << 26)) simd |= 1; if (c & (1u << 19)) simd |= 2; if (c & (1u << 28)) simd |= 4; }
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 5))) simd |= 8;
    printf("using %%s kernels\n", simd & 8 ? "avx2" : simd & 4 ? "avx" : simd & 2 ? "sse4.1" : "scalar");
    return simd;
}'''


def _hn_debugger_tool(r):
    # A tiny tracer: legit debugger-style ptrace use (the tool IS the debugger).
    return r'''
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (argc < 3) return 0;
    pid_t c = fork();
    if (c == 0) { ptrace(PTRACE_TRACEME, 0, 0, 0); execvp(argv[2], argv + 2); _exit(127); }
    int st, n = 0; waitpid(c, &st, 0);
    while (!WIFEXITED(st)) {
        struct user_regs_struct regs; ptrace(PTRACE_GETREGS, c, 0, &regs);
        n++; ptrace(PTRACE_SYSCALL, c, 0, 0); waitpid(c, &st, 0);
    }
    printf("%%d syscall stops\n", n);
    return n;
}'''


def _hn_sysinfo_linux(r):
    return r'''
#include <unistd.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    long cpus = sysconf(_SC_NPROCESSORS_ONLN), pages = sysconf(_SC_PHYS_PAGES), psz = sysconf(_SC_PAGE_SIZE);
    int workers = cpus > 1 ? (int)cpus - 1 : 1;
    printf("%%ld CPUs, %%ld MiB RAM -> %%d worker threads\n", cpus, pages / 1024 * psz / 1024, workers);
    FILE *f = fopen("/proc/meminfo", "r"); char ln[128];
    if (f) { while (fgets(ln, sizeof ln, f)) if (!strncmp(ln, "MemAvailable", 12)) fputs(ln, stdout); fclose(f); }
    return workers;
}'''


def _hn_sysinfo_win(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX ms; ms.dwLength = sizeof ms; GlobalMemoryStatusEx(&ms);
    char name[64]; DWORD n = sizeof name; GetComputerNameA(name, &n);
    printf("%%s: %%lu CPUs, %%llu MiB\n", name, si.dwNumberOfProcessors, ms.ullTotalPhys >> 20);
    return (int)si.dwNumberOfProcessors;
}'''


def _hn_bench(r):
    return r'''
#include <time.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
    volatile double x = 0; for (int i = 0; i < %d; i++) x += i * 0.5;
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("bench: %%.3f ms\n", (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6);
    return (int)x;
}''' % r.randint(1000, 1000000)


def _hn_bench_win(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    DWORD t0 = GetTickCount();
    volatile double x = 0; for (int i = 0; i < %d; i++) x += i * 0.5;
    QueryPerformanceCounter(&b); Sleep(%d);
    printf("bench %%.3f ms (%%lu ticks)\n", (b.QuadPart - a.QuadPart) * 1000.0 / f.QuadPart, GetTickCount() - t0);
    return (int)x;
}''' % (r.randint(1000, 1000000), r.choice([0, 1, 10, 16, 100]))


def _hn_random_table(r):
    # High-entropy embedded data used as data (a noise texture), never decoded/executed.
    n = r.choice([2048, 8192, 32768, 65536])
    blob = bytes(r.getrandbits(8) for _ in range(n))
    return r'''
static const unsigned char @F_noise[%d] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned acc = 0; for (int y = 0; y < 64; y++) acc += @F_noise[(y * 131 + argc) %% %d];
    printf("noise sample %%u\n", acc);
    return (int)(acc & 0xff);
}''' % (n, c_bytes(blob), n)


def _hn_plugins(r):
    lib = r.choice(["libplugin_%s.so", "mod_%s.so", "lib%s-ext.so"]) % _n(r)
    return r'''
#include <dlfcn.h>
__attribute__((noinline)) int @F(int argc, char **argv) {
    void *h = dlopen(argc > 1 ? argv[1] : "%s", RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "plugin: %%s\n", dlerror()); return 0; }
    int (*init)(void) = (int (*)(void))dlsym(h, "plugin_init");
    int r = init ? init() : -1;
    dlclose(h);
    return r;
}''' % lib


def _hn_plugins_win(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HMODULE h = LoadLibraryA(argc > 1 ? argv[1] : "%s.dll");
    if (!h) return 0;
    FARPROC p = GetProcAddress(h, "PluginInit");
    int r = p ? ((int (*)(void))p)() : -1;
    FreeLibrary(h);
    return r;
}''' % _n(r)


def _hn_crc(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned crc = 0xFFFFFFFFu; const unsigned char *p = (const unsigned char *)argv[0];
    for (; *p; p++) { crc ^= *p; for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u))); }
    printf("crc32 %%08x\n", ~crc);
    return (int)(crc & 0xff);
}'''


def _hn_base64(r):
    return r'''
static const char @F_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
__attribute__((noinline)) int @F(int argc, char **argv) {
    const unsigned char *in = (const unsigned char *)(argc > 1 ? argv[1] : "%s"); size_t n = strlen((const char *)in);
    char out[256]; size_t o = 0;
    for (size_t i = 0; i + 2 < n && o + 4 < sizeof out; i += 3) {
        unsigned v = in[i] << 16 | in[i + 1] << 8 | in[i + 2];
        out[o++] = @F_b64[v >> 18 & 63]; out[o++] = @F_b64[v >> 12 & 63]; out[o++] = @F_b64[v >> 6 & 63]; out[o++] = @F_b64[v & 63];
    }
    out[o] = 0; puts(out);
    return (int)o;
}''' % _n(r)


def _hn_vm_helptext(r):
    # Mentions virtualization products in help text (e.g. an installer or deploy tool).
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--platforms")) {
        puts("Supported targets: bare metal, QEMU/KVM guests, VMware ESXi, VirtualBox, Hyper-V, Xen.");
        puts("Images are tested on x86_64 and aarch64.");
        return 1;
    }
    return 0;
}'''


def _hn_xor_checksum(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char buf[64]; unsigned char x = 0;
    for (int i = 0; i < 64; i++) buf[i] = (unsigned char)(i * %d + argc);
    for (int i = 0; i < 64; i++) x ^= buf[i];
    printf("parity %%02x\n", x);
    return x;
}''' % r.randint(3, 250)


def _hn_url_docs(r):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--version")) {
        printf("%%s 1.%d.%d\nReport bugs: https://example.org/%s/issues\nDocs: https://docs.example.org/%s\n", argv[0]);
        return 1;
    }
    return 0;
}''' % (r.randint(0, 20), r.randint(0, 9), _n(r), _n(r))


def _hn_getenv_debug(r):
    # Reads an app-specific DEBUG env var for verbose logging (not debugger detection).
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    const char *d = getenv("%s_DEBUG"); int lvl = d ? atoi(d) : 0;
    if (lvl > 1) fprintf(stderr, "debug logging level %%d\n", lvl);
    return lvl;
}''' % _n(r).upper()


H("cpu_features.v1", "linux", _hn_cpu_features, inc=STD)
H("cpu_features.v2", "windows", _hn_cpu_features, inc=STD)
H("debugger_tool.v1", "linux", _hn_debugger_tool, inc=STD)
H("sysinfo.v1", "linux", _hn_sysinfo_linux, inc=STD)
H("sysinfo.v2", "windows", _hn_sysinfo_win, inc=STD + ("windows.h",))
H("bench.v1", "linux", _hn_bench, inc=STD)
H("bench.v2", "windows", _hn_bench_win, inc=STD + ("windows.h",))
H("random_table.v1", "any", _hn_random_table, inc=STD)
H("plugins.v1", "linux", _hn_plugins, inc=STD)
H("plugins.v2", "windows", _hn_plugins_win, inc=STD + ("windows.h",))
H("crc.v1", "any", _hn_crc, inc=STD)
H("base64.v1", "any", _hn_base64, inc=STD)
H("vm_helptext.v1", "any", _hn_vm_helptext, inc=STD)
H("xor_checksum.v1", "any", _hn_xor_checksum, inc=STD)
H("url_docs.v1", "any", _hn_url_docs, inc=STD)
H("getenv_debug.v1", "any", _hn_getenv_debug, inc=STD)
