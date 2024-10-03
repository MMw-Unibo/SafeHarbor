#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "hello.h"

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

////////////////////////////////////////
// structs
typedef struct ebpf_params ebpf_params;
struct ebpf_params {
    char *maps[8];
    size_t map_count;
    char *progs[8];
    size_t prog_count;
};

typedef struct ebpf_map_table ebpf_map_table;
struct ebpf_map_table {
    char *name;
    struct bpf_map *map;
};

typedef struct ebpf_program ebpf_program;
struct ebpf_program {
    char *name;

    struct bpf_object *obj;

    ebpf_map_table *maps;
    size_t map_count;
    struct bpf_program **progs;
    size_t prog_count;
    struct bpf_link **links;
    size_t link_count;
};

ebpf_program*
ebpf_program_open_and_load(char *filename, ebpf_params *params)
{
    ebpf_program *prog = calloc(1, sizeof(*prog));
    prog->name = filename;

    prog->obj = bpf_object__open(filename);
    if (!prog->obj) {
        fprintf(stderr, "[error] bpf_object__open failed: %s\n", strerror(errno)); 
        goto exit_with_error;
    }

    int ret = bpf_object__load(prog->obj);
    if (ret != 0) {
        fprintf(stderr, "[error] bpf_object__load failed: %s\n", strerror(errno)); 
        goto exit_with_error;
    }

    prog->prog_count = params->prog_count;
    prog->progs      = calloc(prog->prog_count, sizeof(*prog->progs));
    for (size_t i = 0; i < prog->prog_count; ++i) {
        prog->progs[i] = bpf_object__find_program_by_name(prog->obj, params->progs[i]);
        if (!prog->progs[i]) {
            fprintf(stderr, "[error] bpf_object__find_program_by_name failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
    }

    prog->map_count = params->map_count;
    prog->maps      = calloc(prog->map_count, sizeof(*prog->maps));
    for (size_t i = 0; i < prog->map_count; ++i) {
        prog->maps[i].map  = bpf_object__find_map_by_name(prog->obj, params->maps[i]);
        prog->maps[i].name = params->maps[i];
        if (!prog->maps[i].map) {
            fprintf(stderr, "[error] bpf_object__find_map_by_name failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
    }

    // if (bpf_program__pin(prog, "/sys/fs/bpf/hello") != 0) {
    //     fprintf(stderr, "[error] bpf_program__pin failed: %s\n", strerror(errno)); 
    //     return 1;
    // }

    prog->link_count = prog->prog_count;
    prog->links      = calloc(prog->link_count, sizeof(*prog->links));
    for (size_t i = 0; i < prog->prog_count; ++i) {
        prog->links[i] = bpf_program__attach(prog->progs[i]);
        if (!prog->links[i]) {
            fprintf(stderr, "[error] bpf_program__attach failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
    }

    return prog;

exit_with_error:
    free(prog);
    return NULL;
}

static void 
ebpf_program_destroy(ebpf_program *prog)
{
    for (size_t i = 0; i < prog->prog_count; ++i) {
        bpf_link__destroy(prog->links[i]);
        bpf_program__unload(prog->progs[i]);
    }

    free(prog->links);
    free(prog->progs);
    free(prog->maps);

    bpf_object__close(prog->obj);
    free(prog);
}

static struct bpf_map *
ebpf_program_find_map_by_name(ebpf_program *prog, const char *name)
{
    for (size_t i = 0; i < prog->map_count; ++i) {
        if (strcmp(prog->maps[i].name, name) == 0) {
            return prog->maps[i].map;
        }
    }

    return NULL;
}

////////////////////////////////////////
// functions
static void
print_bpf_output(void *ctx, int cpu, void *data, u32 size)
{
    ebpf_program *prog = ctx;

    struct data_t *d = data;
    printf("[info '%s'] pid: %d, uid: %d, command: %s, message: %s, path: %s\n",
           prog->name,
           d->pid, d->uid, d->command, d->message, d->path);
}

////////////////////////////////////////
// globals
#define MAX_MAPS 3
struct bpf_map *maps[MAX_MAPS];
struct hello_rodata {
    char message[14];
} *rodata;
#define MAX_PROGS 1
struct bpf_program *progs[MAX_PROGS];
struct bpf_link *links[MAX_PROGS];
static bool g_run = true;

#define DEFAULT_EBPF_PROGRAMS_DIR "./build/ebpf"

////////////////////////////////////////
// handlers
void
sig_int(int signo)
{
    fprintf(stderr, "[info] signal %d received\n", signo);
    g_run = false;
}

////////////////////////////////////////
int
main(int argc, char *argv[])
{
    char *ebpf_programs_dir = DEFAULT_EBPF_PROGRAMS_DIR;
    if (argc == 2) {
        ebpf_programs_dir = argv[1];
    }

    signal(SIGINT, sig_int);

    ebpf_params params = {
        .maps       = { "output", "my_config" },
        .map_count  = 2,
        .progs      = { "hello" },
        .prog_count = 1,
    };

    char filename[256];
    snprintf(filename, sizeof(filename), "%s/hello.bpf.o", ebpf_programs_dir);

    ebpf_program *prog = ebpf_program_open_and_load(filename, &params);
    if (!prog) {
        fprintf(stderr, "[error] ebpf_program_open_and_load failed: %s\n", strerror(errno)); 
        return 1;
    }

    struct bpf_map *output = ebpf_program_find_map_by_name(prog, "output");
    if (!output) {
        fprintf(stderr, "[error] ebpf_program_find_map_by_name failed: %s\n", strerror(errno)); 
        return 1;
        goto cleanup;
    }

    struct perf_buffer *pb;
    pb = perf_buffer__new(bpf_map__fd(output), 8, print_bpf_output, NULL, (void *)prog, NULL);
    int ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "[error] perf_buffer__new failed: %s\n", strerror(errno)); 
        goto cleanup;
    }

    while (g_run) {
        while (perf_buffer__poll(pb, 1000) > 0) {
        }
    }

cleanup:
    perf_buffer__free(pb);
    ebpf_program_destroy(prog);
    return 0;
}