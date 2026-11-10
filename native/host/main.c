// ztnx-c: host build of the C driver + FFI, for testing on the development
// machine exactly the code paths the Switch sysmodule uses.
//
//   ztnx-c --conf FILE [--port N] [--echo-test <peer ip>] [--sleep-test]
//   ztnx-c --update-check VERSION   (GitHub release check, as at boot)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ztnx.h"
#include "ztnx_app.h"
#include "ztnx_driver.h"
#include "ztnx_update.h"

void ztnx_platform_random(uint8_t *buf, size_t len) { arc4random_buf(buf, len); }

static const char *arg(int argc, char **argv, const char *name) {
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return NULL;
}

static int has(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], name)) return 1;
    return 0;
}

static int g_handshakes;

static void on_event(void *ctx, const ZtnxEvent *ev) {
    (void)ctx;
    static const char *names[] = {"log", "addresses", "peers", "error", "resolve", "handshake", "peer-lost"};
    const char *name = ev->kind < sizeof names / sizeof *names ? names[ev->kind] : "?";
    if (ev->kind == ZTNX_EVENT_HANDSHAKE) g_handshakes++;
    printf("[event] %s value=%u %s\n", name, ev->value, ev->text);
    fflush(stdout);
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    *len = fread(buf, 1, (size_t)n, f);
    buf[*len] = 0;
    fclose(f);
    return buf;
}

// The sysmodule's boot-time update check, with `current` as our version.
static int update_check(const char *current) {
    uint8_t seed[32];
    ztnx_platform_random(seed, sizeof seed);
    ztnx_seed_rng(seed);
    ztnx_set_unix_time((uint64_t)time(NULL));
    ZtnxUpdate *u = ztnx_update_start(ZTNX_UPDATE_REPO, current, ztnx_driver_now_ns(), 30000);
    if (!u) return 1;
    int r;
    while ((r = ztnx_update_step(u, ztnx_driver_now_ns())) == ZTNX_UPDATE_PENDING) usleep(50000);
    if (r == ZTNX_UPDATE_FAILED) printf("update check failed: %s\n", ztnx_update_error(u));
    else printf("latest %s: %s\n", ztnx_update_latest(u), r == ZTNX_UPDATE_NEWER ? "newer" : "not newer");
    ztnx_update_free(u);
    return r == ZTNX_UPDATE_FAILED;
}

int main(int argc, char **argv) {
    const char *update_version = arg(argc, argv, "--update-check");
    if (update_version) return update_check(update_version);
    const char *conf_path = arg(argc, argv, "--conf");
    if (!conf_path) {
        fprintf(stderr, "usage: %s --conf FILE [--port N] [--echo-test IP] [--sleep-test]\n       %s --update-check VERSION\n", argv[0], argv[0]);
        return 2;
    }
    uint8_t seed[32];
    ztnx_platform_random(seed, sizeof seed);
    ztnx_seed_rng(seed);

    size_t conf_len = 0;
    char *conf = read_file(conf_path, &conf_len);
    if (!conf) {
        fprintf(stderr, "cannot read %s\n", conf_path);
        return 1;
    }
    bool corrected = false;
    uint64_t unix_time = ztnx_sane_unix_time((uint64_t)time(NULL), ZTNX_UPDATE_HOST, &corrected);
    if (corrected) fprintf(stderr, "warning: system clock implausible; using %s's Date\n", ZTNX_UPDATE_HOST);
    if (unix_time == 0) unix_time = (uint64_t)time(NULL);
    ZtnxEngine *engine = ztnx_engine_new(ztnx_driver_now_ns(), unix_time);
    ZtnxConfig cfg = {.conf = conf, .conf_len = conf_len};
    char err[160];
    if (!ztnx_engine_reload(engine, &cfg, ztnx_driver_now_ns(), err, sizeof err)) {
        fprintf(stderr, "%s: %s\n", conf_path, err);
        return 1;
    }
    free(conf);
    ZtnxDriver *driver = ztnx_driver_new(engine, on_event, NULL);
    const char *port = arg(argc, argv, "--port");
    uint16_t udp_port = port ? (uint16_t)atoi(port) : ztnx_engine_listen_port(engine);
    if (ztnx_driver_open_udp(driver, udp_port) != 0 && ztnx_driver_open_udp(driver, 0) != 0) {
        fprintf(stderr, "cannot open a UDP socket\n");
        return 1;
    }

    const char *echo_ip = arg(argc, argv, "--echo-test");
    const int sleep_test = has(argc, argv, "--sleep-test");
    ZtnxAddr target;
    if (echo_ip && ztnx_parse_ipv4(echo_ip, 7, &target) != 0) {
        fprintf(stderr, "bad --echo-test address\n");
        return 2;
    }
    ZtnxEcho echo;
    int round = 0;  // 0: first echo; 1: after a suspend/resume (--sleep-test)
    uint64_t resumed_ns = 0;
    if (echo_ip) ztnx_echo_init(&echo, &target);
    for (;;) {
        if (ztnx_driver_run_once(driver, 50) != 0) {
            fprintf(stderr, "driver error\n");
            return 1;
        }
        if (!echo_ip) continue;
        int r = ztnx_echo_step(&echo, engine, ztnx_driver_now_ns());
        if (!r) continue;
        if (r < 0) {
            printf("echo test FAILED%s\n", round ? " after resume" : "");
            return 1;
        }
        if (round == 0 && sleep_test) {
            // What the console does around sleep: close the socket, idle,
            // reopen it and contact the peers again.
            printf("echo test PASSED; suspending 5 s\n");
            fflush(stdout);
            ztnx_driver_suspend(driver);
            sleep(5);
            ztnx_driver_resume(driver);
            resumed_ns = ztnx_driver_now_ns();
            ztnx_engine_network_up(engine, resumed_ns);
            ztnx_echo_init(&echo, &target);
            round = 1;
            continue;
        }
        if (round == 1) {
            double secs = (double)(ztnx_driver_now_ns() - resumed_ns) / 1e9;
            printf("echo test PASSED after resume in %.2f s\n", secs);
            return secs < 3.0 ? 0 : 1;
        }
        printf("echo test PASSED\n");
        return 0;
    }
}
