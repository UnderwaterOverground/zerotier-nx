// ztnx-app: homebrew front end for the ztnx engine (a developer tool).
//
// Brings up the tunnel from sdmc:/config/zerotier-nx/<conf> and shows
// status. Buttons: Y = echo self-test against the `echo_test` peer,
// X = crypto benchmark, + = exit. Run with `nxlink -s ztnx-app.nro` to stream
// the log back to the development machine.
//
// config.ini (next to the .conf):
//   conf=wg0.conf             (default)
//   echo_test=10.7.0.1        (optional; a peer running TCP/UDP echo on port 7)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <switch.h>

#include "ztnx.h"
#include "ztnx_app.h"
#include "ztnx_driver.h"
#include "ztnx_update.h"

#define CONFIG_DIR "sdmc:/config/zerotier-nx"
#define CONFIG_PATH CONFIG_DIR "/config.ini"

typedef struct {
    char conf[64];
    char echo_test[64];
} Config;

void ztnx_platform_random(uint8_t *buf, size_t len) { randomGet(buf, len); }

_Noreturn void ztnx_platform_panic(const uint8_t *msg, size_t len) {
    printf("\nPANIC in ztnx core: %.*s\n", (int)len, (const char *)msg);
    consoleUpdate(NULL);
    fflush(stdout);
    svcSleepThread(5000000000ULL);
    abort();
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) s[--n] = 0;
}

static void load_config(Config *c) {
    memset(c, 0, sizeof *c);
    strcpy(c->conf, "wg0.conf");
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) return;
    char line[320];
    while (fgets(line, sizeof line, f)) {
        trim(line);
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#') continue;
        *eq = 0;
        const char *v = eq + 1;
        if (!strcmp(line, "conf")) snprintf(c->conf, sizeof c->conf, "%s%s", v, strstr(v, ".conf") ? "" : ".conf");
        if (!strcmp(line, "echo_test")) snprintf(c->echo_test, sizeof c->echo_test, "%s", v);
    }
    fclose(f);
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = n > 0 ? malloc((size_t)n + 1) : NULL;
    *len = buf ? fread(buf, 1, (size_t)n, f) : 0;
    if (buf) buf[*len] = 0;
    fclose(f);
    return buf;
}

static void on_event(void *ctx, const ZtnxEvent *ev) {
    int *handshakes = ctx;
    switch (ev->kind) {
        case ZTNX_EVENT_ADDRESSES:
            printf("Tunnel address: \x1b[36m%s\x1b[0m\n", ev->text);
            break;
        case ZTNX_EVENT_PEERS:
            printf("Peers: %u\n", ev->value);
            break;
        case ZTNX_EVENT_RESOLVE:
            printf("Resolving %s...\n", ev->text);
            break;
        case ZTNX_EVENT_HANDSHAKE:
            (*handshakes)++;
            printf("\x1b[32mHandshake with %s.\x1b[0m\n", ev->text);
            break;
        case ZTNX_EVENT_PEER_LOST:
            printf("\x1b[33m%s stopped answering; handshaking again.\x1b[0m\n", ev->text);
            break;
        case ZTNX_EVENT_ERROR:
            printf("\x1b[31m%s\x1b[0m\n", ev->text);
            break;
        default:
            printf("%s\n", ev->text);
    }
}

// The network clock if it has been synced (QuickNTP / Nintendo NTP), else the
// user-set clock.
static uint64_t console_unix_time(void) {
    u64 t = 0;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_NetworkSystemClock, &t)) && t > (u64)ZTNX_BUILD_UNIX) return t;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_UserSystemClock, &t))) return t;
    return (uint64_t)time(NULL);
}

static const char *fmt_date(uint64_t t) {
    static char buf[2][32];
    static int i;
    i ^= 1;
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(buf[i], sizeof buf[i], "%Y-%m-%d %H:%M UTC", &tm);
    return buf[i];
}

static void log_line(uint32_t level, const char *msg) {
    printf(level <= 2 ? "\x1b[33m%s\x1b[0m\n" : "%s\n", msg);
}

static void run_bench(void) {
    const size_t packet_len = 1400;
    const u32 packets = 4000;
    u64 start = armGetSystemTick();
    ztnx_bench_aead(packet_len, packets);
    double secs = (double)armTicksToNs(armGetSystemTick() - start) / 1e9;
    printf("chacha20poly1305: %.1f Mbit/s\n", (double)(packet_len * packets) * 8.0 / secs / 1e6);
    start = armGetSystemTick();
    ztnx_bench_x25519(200);
    secs = (double)armTicksToNs(armGetSystemTick() - start) / 1e9;
    printf("x25519: %.0f ops/s\n", 200 / secs);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    consoleInit(NULL);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    Result rc = socketInitializeDefault();
    if (R_SUCCEEDED(rc)) nxlinkStdio();
    printf("zerotier-nx %s\n", ztnx_version());
    // Core log lines at info level and above.
    ztnx_set_log_callback(log_line, 3);

    u8 seed[32];
    randomGet(seed, sizeof seed);
    ztnx_seed_rng(seed);
    u32 st = ztnx_selftest();
    if (st != ZTNX_SELFTEST_OK) printf("\x1b[31mcrypto selftest FAILED (%u)\x1b[0m\n", st);

    Config cfg;
    load_config(&cfg);
    char conf_path[128];
    snprintf(conf_path, sizeof conf_path, "%s/%s", CONFIG_DIR, cfg.conf);
    ZtnxEngine *engine = NULL;
    ZtnxDriver *driver = NULL;
    int handshakes = 0;
    size_t conf_len = 0;
    char *conf = NULL;
    if (R_FAILED(rc)) {
        printf("socketInitializeDefault failed: 0x%x\n", rc);
    } else if (!(conf = read_file(conf_path, &conf_len))) {
        printf("\x1b[31mcannot read %s\x1b[0m\nPut a wg-quick style .conf there (see the README).\n", conf_path);
    } else {
        uint64_t now_unix = console_unix_time();
        bool corrected = false;
        uint64_t unix_time = ztnx_sane_unix_time(now_unix, ZTNX_UPDATE_HOST, &corrected);
        if (corrected) {
            printf("\x1b[33mConsole clock looks wrong (%s); using %s's time (%s).\n"
                   "Fix it with the QuickNTP overlay to avoid this.\x1b[0m\n",
                   fmt_date(now_unix), ZTNX_UPDATE_HOST, fmt_date(unix_time));
        } else if (unix_time == 0) {
            printf("\x1b[31mConsole clock looks wrong (%s) and %s's time is unavailable.\n"
                   "Set the clock (QuickNTP overlay or System Settings).\x1b[0m\n",
                   fmt_date(now_unix), ZTNX_UPDATE_HOST);
            unix_time = now_unix;
        }
        engine = ztnx_engine_new(ztnx_driver_now_ns(), unix_time);
        ZtnxConfig wc = {.conf = conf, .conf_len = conf_len};
        char err[160];
        if (!ztnx_engine_reload(engine, &wc, ztnx_driver_now_ns(), err, sizeof err)) {
            printf("\x1b[31m%s: %s\x1b[0m\n", cfg.conf, err);
        } else {
            printf("Config: %s\n", cfg.conf);
            driver = ztnx_driver_new(engine, on_event, &handshakes);
            const uint16_t port = ztnx_engine_listen_port(engine);
            if (driver && ztnx_driver_open_udp(driver, port) != 0 && ztnx_driver_open_udp(driver, 0) != 0) {
                printf("\x1b[31mno UDP socket\x1b[0m\n");
                ztnx_driver_free(driver);
                driver = NULL;
            }
        }
        free(conf);
    }
    printf("\nY: echo test   X: benchmark   +: exit\n\n");

    ZtnxEcho echo;
    bool echo_running = false;
    while (appletMainLoop()) {
        padUpdate(&pad);
        u64 down = padGetButtonsDown(&pad);
        if (down & HidNpadButton_Plus) break;
        if (down & HidNpadButton_X) run_bench();
        if ((down & HidNpadButton_Y) && driver) {
            ZtnxAddr target;
            if (!cfg.echo_test[0] || ztnx_parse_ipv4(cfg.echo_test, 7, &target) != 0) {
                printf("set echo_test=<peer ip> in config.ini\n");
            } else if (handshakes == 0) {
                printf("no handshake with a peer yet\n");
            } else {
                printf("echo test against %s:7 ...\n", cfg.echo_test);
                ztnx_echo_init(&echo, &target);
                echo_running = true;
            }
        }
        if (driver) {
            // Short waits keep the UI responsive; the engine is event-driven.
            if (ztnx_driver_run_once(driver, 16) != 0) printf("driver error\n");
            if (echo_running) {
                int r = ztnx_echo_step(&echo, engine, ztnx_driver_now_ns());
                if (r) {
                    printf(r > 0 ? "\x1b[32mecho test PASSED\x1b[0m\n" : "\x1b[31mecho test FAILED\x1b[0m\n");
                    echo_running = false;
                }
            }
        }
        consoleUpdate(NULL);
    }

    ztnx_driver_free(driver);
    ztnx_engine_free(engine);
    socketExit();
    consoleExit(NULL);
    return 0;
}
