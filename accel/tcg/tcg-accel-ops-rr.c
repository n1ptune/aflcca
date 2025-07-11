/*
 * QEMU TCG Single Threaded vCPUs implementation
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2014 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "sysemu/tcg.h"
#include "sysemu/replay.h"
#include "sysemu/cpu-timers.h"
#include "qemu/main-loop.h"
#include "qemu/notify.h"
#include "qemu/guest-random.h"
#include "exec/exec-all.h"
#include "tcg/startup.h"
#include "tcg-accel-ops.h"
#include "tcg-accel-ops-rr.h"
#include "tcg-accel-ops-icount.h"
#include "afl.h"
#include "exec/ramblock.h"

/* Kick all RR vCPUs */
void rr_kick_vcpu_thread(CPUState *unused)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        cpu_exit(cpu);
    };
}

/*
 * TCG vCPU kick timer
 *
 * The kick timer is responsible for moving single threaded vCPU
 * emulation on to the next vCPU. If more than one vCPU is running a
 * timer event we force a cpu->exit so the next vCPU can get
 * scheduled.
 *
 * The timer is removed if all vCPUs are idle and restarted again once
 * idleness is complete.
 */

static QEMUTimer *rr_kick_vcpu_timer;
static CPUState *rr_current_cpu;

static inline int64_t rr_next_kick_time(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + TCG_KICK_PERIOD;
}

/* Kick the currently round-robin scheduled vCPU to next */
static void rr_kick_next_cpu(void)
{
    CPUState *cpu;
    do {
        cpu = qatomic_read(&rr_current_cpu);
        if (cpu) {
            cpu_exit(cpu);
        }
        /* Finish kicking this cpu before reading again.  */
        smp_mb();
    } while (cpu != qatomic_read(&rr_current_cpu));
}

static void rr_kick_thread(void *opaque)
{
    timer_mod(rr_kick_vcpu_timer, rr_next_kick_time());
    rr_kick_next_cpu();
}

static void rr_start_kick_timer(void)
{
    if (!rr_kick_vcpu_timer && CPU_NEXT(first_cpu)) {
        rr_kick_vcpu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           rr_kick_thread, NULL);
    }
    if (rr_kick_vcpu_timer && !timer_pending(rr_kick_vcpu_timer)) {
        timer_mod(rr_kick_vcpu_timer, rr_next_kick_time());
    }
}

static void rr_stop_kick_timer(void)
{
    if (rr_kick_vcpu_timer && timer_pending(rr_kick_vcpu_timer)) {
        timer_del(rr_kick_vcpu_timer);
    }
}

static void rr_wait_io_event(void)
{
    CPUState *cpu;

    while (all_cpu_threads_idle()) {
        rr_stop_kick_timer();
        qemu_cond_wait_bql(first_cpu->halt_cond);
    }

    rr_start_kick_timer();

    CPU_FOREACH(cpu) {
        qemu_wait_io_event_common(cpu);
    }
}

/*
 * Destroy any remaining vCPUs which have been unplugged and have
 * finished running
 */
static void rr_deal_with_unplugged_cpus(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu->unplug && !cpu_can_run(cpu)) {
            tcg_cpu_destroy(cpu);
            break;
        }
    }
}

static void rr_force_rcu(Notifier *notify, void *data)
{
    rr_kick_next_cpu();
}

/*
 * Calculate the number of CPUs that we will process in a single iteration of
 * the main CPU thread loop so that we can fairly distribute the instruction
 * count across CPUs.
 *
 * The CPU count is cached based on the CPU list generation ID to avoid
 * iterating the list every time.
 */
static int rr_cpu_count(void)
{
    static unsigned int last_gen_id = ~0;
    static int cpu_count;
    CPUState *cpu;

    QEMU_LOCK_GUARD(&qemu_cpu_list_lock);

    if (cpu_list_generation_id_get() != last_gen_id) {
        cpu_count = 0;
        CPU_FOREACH(cpu) {
            ++cpu_count;
        }
        last_gen_id = cpu_list_generation_id_get();
    }

    return cpu_count;
}
static QemuThread *single_tcg_cpu_thread;
// void ram_block_remap_all(void)
// {
//     RAMBlock *block;

//     RAMBLOCK_FOREACH(block) {
//         void *old_host = block->host;

//         if (block->fd >= 0) {
//             // 文件后端内存：先解除旧映射，再创建新映射

//             // 1. 解除从父进程继承来的、地址可能已无效的映射
//             if (munmap(old_host, block->max_length) != 0) {
//                 printf("munmap failed for %s: %s",
//                        block->idstr, strerror(errno));
//                 // 这是一个严重错误，通常应该中止
//                 exit(1);
//             }
            
//             // 2. 创建新映射，让内核为我们选择一个合适的地址 (传入 NULL)
//             void *new_host = mmap(NULL, block->max_length, // <-- 地址传 NULL
//                                   PROT_READ | PROT_WRITE,
//                                   MAP_SHARED, // <-- 不再使用 MAP_FIXED
//                                   block->fd, block->offset); // 使用在文件内的偏移

//             if (new_host == MAP_FAILED) {
//                 printf("RAMBlock remap mmap failed for %s: %s",
//                        block->idstr, strerror(errno));
//                 exit(1);
//             }
//             // 3. 更新 block->host 为内核分配的新地址
//             block->host = new_host;
//         } else {
//             // 匿名内存：确保可写 (这部分逻辑保持不变)
//             // if (mprotect(old_host, block->used_length, 
//             //              PROT_READ | PROT_WRITE) < 0) {
//             //     printf("mprotect failed for %s: %s",
//             //            block->idstr, strerror(errno));
//             // }
//             printf("no fd\n");
//         }
        
//         // 更新关联数据结构 (保持不变)
//         if (block->mr) {
//             block->mr->ram_block = block;
//         }
        
//         printf("Remapped RAMBlock %s: %p -> %p\n", 
//                block->idstr, old_host, block->host);
//     }

// }

void gotPipeNotification(void *ctx)
{
    //qemu_mutex_lock_iothread();
    // qemu_log("PIPE Notification here!!!\n");
    CPUArchState *env;
    char buf[4];

    /* cpu thread asked us to run AFL forkserver */
    if(read(afl_qemuloop_pipe[0], buf, 4) != 4) {
        qemu_log("error reading afl/qemu pipe!\n");
        exit(1);
    }

    // qemu_log("PIPE Notification start up afl forkserver! pid %d\n", getpid());
    afl_setup();
    env = NULL; //XXX for now.. if we want to share JIT to the parent we will need to pass in a real env here
    //env = restart_cpu->env_ptr;
    afl_forkserver(restart_cpu);

    /* we're now in the child! */
    //tcg_cpu_thread = NULL;
    //(CPUState *)(first_cpu) = restart_cpu;

    // qemu_log("PIPE Notification after afl fork being CHILD %d \n", getpid());
    //restart_cpu->as = NULL;

    single_tcg_cpu_thread = NULL;
    
    (&cpus_queue)->tqh_first = restart_cpu;

    // qemu_log("pc..%lx \n", cpu_env(restart_cpu)->pc);
    

    qemu_init_vcpu(restart_cpu);
    
    // ram_block_remap_all();
    // tlb_flush(restart_cpu);
    // tb_flush(restart_cpu);

    // qemu_log("PIPE Notification after qemu_init_vcpu \n");
    //qemu_clock_warp(QEMU_CLOCK_VIRTUAL);
    /* continue running iothread in child process... */
}
/*
 * In the single-threaded case each vCPU is simulated in turn. If
 * there is more than a single vCPU we create a simple timer to kick
 * the vCPU and ensure we don't get stuck in a tight loop in one vCPU.
 * This is done explicitly rather than relying on side-effects
 * elsewhere.
 */
int afl_qemuloop_pipe[2];
CPUState *restart_cpu = NULL;
static void *rr_cpu_thread_fn(void *arg)
{
    // qemu_log("rr_cpu_thread_fn\n");
    Notifier force_rcu;
    CPUState *cpu = arg;

    assert(tcg_enabled());
    rcu_register_thread();
    force_rcu.notify = rr_force_rcu;
    rcu_add_force_rcu_notifier(&force_rcu);
    tcg_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);

    cpu->thread_id = qemu_get_thread_id();
    cpu->neg.can_do_io = true;
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    /* wait for initial kick-off after machine start */
    
    if(!afl_fork_child)  {
        while (first_cpu->stopped) {
        qemu_cond_wait_bql(first_cpu->halt_cond);

            /* process any pending work */
            CPU_FOREACH(cpu) {
                current_cpu = cpu;
                qemu_wait_io_event_common(cpu);
            }
        }
    }

    rr_start_kick_timer();

    cpu = first_cpu;

    /* process any pending work */
    cpu->exit_request = 1;

    while (1) {
        /* Only used for icount_enabled() */
        int64_t cpu_budget = 0;


        if(!afl_fork_child)  {
            bql_unlock();
            replay_mutex_lock();
            bql_lock();
        }
        

        // if (icount_enabled()) {
        //     int cpu_count = rr_cpu_count();

        //     /* Account partial waits to QEMU_CLOCK_VIRTUAL.  */
        //     icount_account_warp_timer();
        //     /*
        //      * Run the timers here.  This is much more efficient than
        //      * waking up the I/O thread and waiting for completion.
        //      */
        //     icount_handle_deadline();

        //     cpu_budget = icount_percpu_budget(cpu_count);
        // }

        if(!afl_fork_child)  {
            replay_mutex_unlock();
        }

        if(afl_fork_child) {
            cpu->exit_request = 0;
            cpu->stop = false;
            cpu->stopped = false;
        }

        if (!cpu) {
            cpu = first_cpu;
        }

        while (cpu && cpu_work_list_empty(cpu) && !cpu->exit_request) {
            /* Store rr_current_cpu before evaluating cpu_can_run().  */
            qatomic_set_mb(&rr_current_cpu, cpu);

            current_cpu = cpu;

            qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
                              (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);

            if (cpu_can_run(cpu)) {
                int r;
                bql_unlock();
                //if (icount_enabled()) {
                //    icount_prepare_for_run(cpu);
                //}
                //qemu_log("rr_thread executing tcg cpus exec \n");
                //qemu_log("rr_thread executing cpu exec return 0x%lx \n", r);
                //if (icount_enabled()) {
                //    icount_process_data(cpu);
                //}
                // bql_lock();
                // if (icount_enabled()) {
                //     icount_prepare_for_run(cpu, cpu_budget);
                // }
                // qemu_log("cpu pc..%lx\n", cpu_env(cpu)->pc);
                r = tcg_cpu_exec(cpu);
                // qemu_log("rr cpu thread\n");
                // if (icount_enabled()) {
                //     icount_process_data(cpu);
                // }
                bql_lock();

                if (r == EXCP_DEBUG) {
                    cpu_handle_guest_debug(cpu);
                    break;
                } else if (r == EXCP_ATOMIC) {
                    bql_unlock();
                    cpu_exec_step_atomic(cpu);
                    bql_lock();
                    break;
                }
                else if (r == AFL_ENTRY_HIT) {
                    qemu_log("Hit afl cpu loop\n");
                    // ask to run forkserver
                    
                    // save context of cpu
                    restart_cpu = (&cpus_queue)->tqh_first;

                    (&cpus_queue)->tqh_first = NULL;

                    // notify iothread
                    if(write(afl_qemuloop_pipe[1], "FORK", 4) != 4) {
                        qemu_log("write afl_qemuloop_pipe failed\n");
                    }
                    afl_qemuloop_pipe[1] = -1;


                    //qatomic_set(&rr_current_cpu, NULL);

                    //restart_cpu->thread = NULL;
                    //cpu->thread = NULL;

                    //qatomic_mb_set(&cpu->exit_request, 0);
                    // qemu_log("Waiting cpu thread for io event then exit...\n");

                    //qemu_notify_event();

                    qemu_wait_io_event(cpu);

                    //tcg_cpus_destroy(cpu);
                    //rr_deal_with_unplugged_cpus();

                    //rcu_unregister_thread();
                    // qemu_log("restart pc..%lx %lx \n", cpu_env(cpu)->pc, cpu_env(restart_cpu)->pc);
                    bql_unlock();
                    rcu_unregister_thread();
                    sleep(1);
                    return NULL;
                }
            } else if (cpu->stop) {
                if (cpu->unplug) {
                    cpu = CPU_NEXT(cpu);
                }
                break;
            }

            // cpu = CPU_NEXT(cpu);
        } /* while (cpu && !cpu->exit_request).. */

        /* Does not need a memory barrier because a spurious wakeup is okay.  */
        qatomic_set(&rr_current_cpu, NULL);

        if (cpu && cpu->exit_request) {
            qatomic_set_mb(&cpu->exit_request, 0);
        }

        if (icount_enabled() && all_cpu_threads_idle()) {
            /*
             * When all cpus are sleeping (e.g in WFI), to avoid a deadlock
             * in the main_loop, wake it up in order to start the warp timer.
             */
            qemu_notify_event();
        }

        rr_wait_io_event();
        rr_deal_with_unplugged_cpus();
    }

    rcu_unregister_thread();
    return NULL;
}

void rr_start_vcpu_thread(CPUState *cpu)
{
    // qemu_log("rr_start_vcpu_thread: %d\n", cpu->cpu_index);
    char thread_name[VCPU_THREAD_NAME_SIZE];
    static QemuCond *single_tcg_halt_cond;

    g_assert(tcg_enabled());
    tcg_cpu_init_cflags(cpu, false);

    if (!single_tcg_cpu_thread) {
        // qemu_log("rr_start_vcpu_thread: creating single TCG thread\n");
        cpu->thread = g_malloc0(sizeof(QemuThread));
        cpu->halt_cond = g_malloc0(sizeof(QemuCond));
        qemu_cond_init(cpu->halt_cond);

        /* share a single thread for all cpus with TCG */
        snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "ALL CPUs/TCG");
        qemu_thread_create(cpu->thread, thread_name,
                           rr_cpu_thread_fn,
                           cpu, QEMU_THREAD_JOINABLE);
        single_tcg_halt_cond = cpu->halt_cond;
        single_tcg_cpu_thread = cpu->thread;
    } else {
        /* we share the thread, dump spare data */
        cpu->thread = single_tcg_cpu_thread;
        cpu->halt_cond = single_tcg_halt_cond;

        /* copy the stuff done at start of rr_cpu_thread_fn */
        cpu->thread_id = first_cpu->thread_id;
        cpu->neg.can_do_io = 1;
        cpu->created = true;
    }
}
