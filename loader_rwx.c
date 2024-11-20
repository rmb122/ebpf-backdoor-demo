#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <sys/mman.h>
#include <unistd.h>

char *read_all(FILE *fp) {
    size_t current_size = 1024;
    size_t current_pos = 0;
    char *buffer = malloc(current_size);

    while (!feof(fp)) {
        current_pos += fread(buffer + current_pos, 1, current_size - current_pos, fp);
        if (current_pos == current_size) {
            current_size *= 2;
            buffer = realloc(buffer, current_size);
        }
    }

    buffer[current_pos + 1] = '\0';
    return buffer;
}

void make_rwx_mem() {
    char *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("rwx page: %p\n", addr);
    addr[3] = '\xde';
    addr[2] = '\xad';
    addr[1] = '\xbe';
    addr[0] = '\xef';
}

int main(void) {
    printf("pid: %d\n", getpid());

    make_rwx_mem();
    FILE *maps = fopen("/proc/self/maps", "r");
    char *content = read_all(maps);
    fclose(maps);
    printf("%s\n", content);
    free(content);

    int fd = bpf_obj_get("/sys/fs/bpf/ebpf_backdoor_rwx");
    int ctx_in = 1234;
    struct bpf_test_run_opts ops = {
            .sz = sizeof(struct bpf_test_run_opts),
            .ctx_in = &ctx_in,
            .ctx_size_in = 4,
    };
    int ret = bpf_prog_test_run_opts(fd, &ops);
    printf("bpf ret code: %d\n", ret);
    return 0;
}
