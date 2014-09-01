#include <map>
#include <fstream>
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))


struct MAPPING_REGION
{
	MAPPING_REGION() 
		: 
			_tid(0), _start(0), _end(0), _size(0), _nr_pages(0), _prot(0), _flags(0), _fd(0), _offset(0)
	{}
	MAPPING_REGION(THREADID tid, ADDRINT start, ADDRINT end, ADDRINT size, ADDRINT nr_pages, ADDRINT prot, ADDRINT flags, ADDRINT fd, ADDRINT offset)
		:
			_tid(tid), _start(start), _end(end), _size(size), _nr_pages(nr_pages), _prot(prot), _flags(flags), _fd(fd), _offset(offset)
	{}

	THREADID _tid;
	ADDRINT _start;
	ADDRINT _end;
	ADDRINT _size;
	ADDRINT _nr_pages;
	ADDRINT _prot;
	ADDRINT _flags;
	ADDRINT _fd;
	ADDRINT _offset;
};

ofstream outFile("test.log");

/*!
 * A container which can hold one pending system call for each thread.
 */
class MAPPING_REGIONS
{
	public:
		MAPPING_REGIONS()
		{
			PIN_InitLock(&_lock);
			prev_pg_addr = 0;
		}

		~MAPPING_REGIONS()
		{
			outFile.close();
		}

		ADDRINT Add(unsigned long addr, const MAPPING_REGION &region)
		{
			ADDRINT ret = 0;
			PIN_GetLock(&_lock, 1);
			MAP::iterator it = _map.find(addr);

			if (it != _map.end())
			{
				ret += 1;
				_map.erase(it);
			}

			_map[addr] = region;
			PIN_ReleaseLock(&_lock);
			return ret;
		}

		BOOL Remove(unsigned long addr, MAPPING_REGION *region)
		{
			PIN_GetLock(&_lock, 1);
			MAP::iterator it = _map.find(addr);
			if (it == _map.end())
			{
				PIN_ReleaseLock(&_lock);
				return FALSE;
			}

			*region = (*it).second;
			_map.erase(it);
			PIN_ReleaseLock(&_lock);
			return TRUE;
		}

		// 수정 중....
		BOOL FindRegion(unsigned long addr, MAPPING_REGION *region)
		{
			PIN_GetLock(&_lock, 1);
			MAP::iterator it;

			//outFile << "======================" << std::endl;
			//outFile << "step 1" << std::endl;
			if (prev_pg_addr <= addr && addr < (prev_pg_addr + PAGE_SIZE))
			{
			//	outFile << "step 2 (OK)" << std::endl;
				PIN_ReleaseLock(&_lock);
				return FALSE;
			}
			
			//outFile << "step 3" << std::endl;
			for (it = _map.begin(); it != _map.end(); it++)
			{
				*region = (*it).second;
				
				if (region->_start <= addr && addr < region->_end)
				{
					/*
					outFile << "accessed addr: " << (void *)addr
						<< ", region base: " << (void *)(region->_start)
						<< ", region end: " << (void *)(region->_end)
						<< std::endl;
						*/
					
					prev_pg_addr = PAGE_MASK & addr;
					//outFile << "step 4 (OK)" << std::endl;
					PIN_ReleaseLock(&_lock);
					return TRUE;
				}
			}
			//outFile << "step 5 (OK)" << std::endl;
			PIN_ReleaseLock(&_lock);
			return FALSE;
		}

	private:
		PIN_LOCK _lock;

		typedef std::map<unsigned long, MAPPING_REGION> MAP;
		MAP _map;
		unsigned long prev_pg_addr;
};
