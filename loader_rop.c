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

int main(void) {
    printf("pid: %d\n", getpid());

    FILE *maps = fopen("/proc/self/maps", "r");
    char *content = read_all(maps);
    fclose(maps);
    printf("%s\n", content);
    free(content);

    maps = fopen("./loader_rop_trigger", "r");
    content = read_all(maps);
    fclose(maps);
    printf("%s\n", content);
    free(content);
    return 0;
}
