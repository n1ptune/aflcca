//#include "exec/target_long.h"
typedef uint64_t afl_ulong;
extern afl_ulong afl_start_code;
extern afl_ulong afl_end_code;
extern afl_ulong afl_entry_point;
extern unsigned char afl_fork_child;
extern int aflEnableTicks;
extern int aflStart;
extern int aflGotLog;
extern const char *aflFile;
extern unsigned long aflPanicAddr;
extern unsigned long aflDmesgAddr;
void afl_setup(void);
void afl_forkserver(CPUState *cpu);

extern int afl_wants_cpu_to_stop;
extern int afl_qemuloop_pipe[2];
extern void gotPipeNotification(void *ctx);
extern CPUState *restart_cpu;
