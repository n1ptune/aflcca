//#include "exec/target_long.h"
typedef uint64_t afl_ulong;
extern afl_ulong afl_start_code, afl_end_code;
extern unsigned char afl_fork_child;
extern int aflEnableTicks;
extern int aflStart;
extern int aflGotLog;
extern const char *aflFile;
extern unsigned long aflPanicAddr;
extern unsigned long aflDmesgAddr;
void afl_setup(void);
void afl_forkserver(void);
