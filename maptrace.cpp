#include "pin.H"
#include "pending_syscalls.H"
#include "mapping_regions.H"
//#include "disasm_container.H"

#include <iostream>
#include <ostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <map>

#define MAP_TRACE	0x100000
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#if defined(TARGET_LINUX)
#   include <sys/syscall.h>
#   include <sys/mman.h>
#   include <sys/time.h>
#   include <asm/ldt.h>
#endif

#if defined(TARGET_LINUX) && defined(TARGET_IA32E)
#   include <asm/prctl.h>
#endif

#if defined(TARGET_ANDROID)
#   define SYS_modify_ldt __NR_modify_ldt
#   define SYS_clone __NR_clone
#endif

// These constants are not defined on old kernels.
//
#ifndef __NR_set_thread_area
#   define __NR_set_thread_area 243
#endif
#ifndef __NR_get_thread_area
#   define __NR_get_thread_area 244
#endif
#ifndef SYS_set_thread_area
#   define SYS_set_thread_area __NR_set_thread_area
#endif
#ifndef SYS_get_thread_area
#   define SYS_get_thread_area __NR_get_thread_area
#endif
#ifndef CLONE_SETTLS
#   define CLONE_SETTLS 0x00080000
#endif

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "maptrace.out", "trace file");

std::ofstream Out;
PENDING_SYSCALLS *PendingSyscalls;  // Holds syscall information between "before" and "after" instrumentation
MAPPING_REGIONS *MappingRegions;

static VOID Instruction(INS, VOID *);
static VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);
static VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);
static VOID SyscallBefore(ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT, THREADID);
static VOID SyscallAfter(ADDRINT, THREADID);
//static VOID RecordMem(VOID *, CHAR, VOID *, INT32, BOOL);
VOID RecordMem(VOID *, VOID *, CHAR);

int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);

    Out.open(KnobOutputFile.Value().c_str());
    PendingSyscalls = new PENDING_SYSCALLS();
    MappingRegions = new MAPPING_REGIONS();

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_StartProgram();
    return 0;
}


static VOID Instruction(INS ins, VOID *v)
{
	// For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
	// instrument the system call instruction.
	//
	if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SyscallBefore), IARG_SYSCALL_NUMBER, 
				IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1, IARG_SYSARG_VALUE, 2, 
				IARG_SYSARG_VALUE, 3, IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
				IARG_THREAD_ID, IARG_END); 

		INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SyscallAfter), IARG_SYSRET_VALUE, 
				IARG_THREAD_ID, IARG_END);
	}

	// Instruments memory accesses using a predicated call, i.e.
	// the instrumentation is called iff the instruction will actually be executed.
	//
	// On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
	// prefixed instructions appear as predicated instructions in Pin.
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	// Iterate over each memory operand of the instruction.
	for (UINT32 memOp = 0; memOp < memOperands; memOp++)
	{
		if (INS_MemoryOperandIsRead(ins, memOp))
		{
			INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_UINT32, 'R',
					IARG_END);
		}
		// Note that in some architectures a single memory operand can be 
		// both read and written (for instance incl (%eax) on IA-32)
		// In that case we instrument it once for read and once for write.
		if (INS_MemoryOperandIsWritten(ins, memOp))
		{
			INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_UINT32, 'W',
					IARG_END);
		}
	}
}

#if 0
static VOID RecordMem(VOID * ip, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{
	Out << ip << ": " << r << " " << setw(2+2*sizeof(ADDRINT)) << addr << " "
		<< dec << setw(2) << size << " "
		<< hex << setw(2+2*sizeof(ADDRINT));
	/*
	   if (!isPrefetch)
	   EmitMem(addr, size);
	 */
	Out << endl;
}
#endif

// Print a memory record
VOID RecordMem(VOID * ip, VOID * addr, CHAR r)
{
	MAPPING_REGION region;

	struct timeval tv;
	struct tm *now;

	unsigned long nr_pages;
	unsigned long pg_start_addr;
	unsigned long pg_offset;

	if (MappingRegions->FindRegion((unsigned long)addr, &region))
	{
		gettimeofday(&tv, NULL);
		now = localtime(&tv.tv_sec);

		nr_pages = region._nr_pages;
		pg_start_addr = PAGE_MASK & (unsigned long)addr;
		pg_offset = ((pg_start_addr - region._start) >> PAGE_SHIFT) + 1;
		
		Out << "time(" << now->tm_hour << ":" << now->tm_min << ":" 
			<< now->tm_sec << "." << (int)(tv.tv_usec/100) 
			<< ") rw(" << r << ") pg_addr("
			<< (void *)pg_start_addr << ") pg_off(" 
			<< pg_offset << "/" << nr_pages << ")" << endl;
			
		Out.flush();
	}
}

static VOID SyscallBefore(ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4,
		ADDRINT arg5, THREADID tid) // args check
{
	switch (num)
	{
		case SYS_mmap:
			PendingSyscalls->Add(tid, PENDING_SYSCALL(num, arg0, arg1, arg2, arg3, arg4, arg5));
			break;

		case SYS_munmap:
			PendingSyscalls->Add((THREADID)tid, PENDING_SYSCALL((ADDRINT)num, arg0, arg1));
			break;
	}
}

static VOID SyscallAfter(ADDRINT ret, THREADID tid) // args check
{
	PENDING_SYSCALL pend;
	MAPPING_REGION region;

	ADDRINT start;
	ADDRINT size;
	ADDRINT end;
	ADDRINT nr_pages;
	ADDRINT prot;
	ADDRINT flags;
	ADDRINT fd;
	ADDRINT offset;

	if (!PendingSyscalls->Remove(tid, &pend)) {
		return;
	}

	switch (pend._number)
	{
		case SYS_mmap:
			if (ret != (ADDRINT)MAP_FAILED)
			{
				start = ret;
				size = pend._arg1;
				end = start + size;
				nr_pages = (size >> PAGE_SHIFT) + 1;
				prot = pend._arg2;
				flags = pend._arg3;
				fd = pend._arg4;
				offset= pend._arg5;

				Out << "mmap (" << (void *)pend._arg0 << ", " << size << ", "
					<< prot << ", " << flags << ", " 
					<< (int)fd << ", " << offset << ") returns:  " 
					<< (void *)ret << std::endl;

				if (pend._arg3 & MAP_TRACE)
				{
					if(MappingRegions->Add(ret, MAPPING_REGION(tid, start, end, size, 
								nr_pages, prot, flags, fd, offset)))
					{
						Out <<  std::endl;
						Out << "change node!!" << std::endl;
					}
					else
					{
						Out <<  std::endl;
						Out << "insert node!!" << std::endl;
					}
				}
			}
			break;

		case SYS_munmap:
			start = pend._arg0;
			size = pend._arg1;

			Out << "munmap (" << (void *)start << ", " << size << ") = " 
				<< (int)ret << std::endl;

			if (MappingRegions->Remove(start, &region))
			{
				Out << "delete node!!" << std::endl;
			}
			break;
	}
}

static VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SyscallBefore(PIN_GetSyscallNumber(ctxt, std),
			PIN_GetSyscallArgument(ctxt, std, 0),
			PIN_GetSyscallArgument(ctxt, std, 1),
			PIN_GetSyscallArgument(ctxt, std, 2),
			PIN_GetSyscallArgument(ctxt, std, 3),
			PIN_GetSyscallArgument(ctxt, std, 4),
			PIN_GetSyscallArgument(ctxt, std, 5),
			threadIndex);
}

static VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SyscallAfter( PIN_GetSyscallReturn(ctxt, std), 
			threadIndex);
}
