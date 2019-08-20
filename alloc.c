#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

struct typedef block{
	size_t prevSize; 
	size_t size; 
	
	BLK* prev; 
	BLK* next; 
}__attribute__((packed)) BLK; 

#define BLS_PREV_SZ_IDX 0 
#define BLK_SZ_IDX 8 
#define BLK_PREV_IDX 16 
#define BLK_NEXT_IDX 24 

#define mdebug //debug 
#define mdebug debug
#define PAGE_TRIM_SZ(size) (((size)%(PAGE_SZ)) ? (((size)&0xfffffffffffff000) + PAGE_SZ) : (size))

#define PAGE_SZ 0x1000
#define BLK_HEADER_SZ 0x10 
#define EMPTY NULL

#define F_BIM_START_SZ 0x20 
#define F_BIN_COUNT 7 
#define F_BIN_INTERVAL 0x10 

#define S_BIN_START_SZ 0x90 
#define S_BIN_COUNT 50 
#define S_BIN_INERVAL 0x10 

#define L_BINS_SZ 0x410 

#define F_IDX_2_SZ(idx) (F_BIN_START_SZ + (idx)*F_BIN_INTERVAL) 
#define F_SZ_2_IDX(size) ((size - F_BIN_START_SZ + 1) / F_BIN_INTERVAL)  
#define F_TRIM_SZ(size) (((size)%(F_BIN_INTERVAL))?((size)&0xfffffffffffff000 + F_BIN_INTERVAL): (size)) 

#define S_IDX_2_SZ(idx) (S_BIN_START_SZ + (idx)*S_BIN_INTERVAL) 
#define S_SZ_2_IDX(size) ((size - S_BIN_START_SZ + 1) / S_BIN_INTERVAL)  
#define S_TRIM_SZ(size) (((size)%(S_BIN_INTERVAL))?((size)&0xfffffffffffff000 + S_BIN_INTERVAL): (size)) 

BLK* fastBins[F_BIN_COUNT] = {EMPTY, }; 
BLK* smallBins[S_BIN_COUNT] = {EMPTY, }; 
BLK* largeBins = EMPTY;  
BLK* unsortedBins = EMPTY; 

uint8_t leftSize = 0; 
void* allocStartPtr = sbrk(0);
void* allocBackupPtr = sbrk(0); 


void initSet(){
	allocStartPtr = sbrk(PAGE_SZ);
	allocBackupPtr = allocStartPtr + PAGE_SZ;
   	leftSize = PAGE_SZ;
	return;
}

void error(const char * errmsg){
	debug("ERROR! %s\n", errmsg);
	abort(); 
}

void* myInternalSbrk(size_t size){
	if(!setting){
		initSet();
	  	setting = 1;
	}
	if( (leftSize-sizeof(size_t)) <= size ) {
		size_t trimSz = PAGE_TRIM_SZ(size);
		allocBackupPtr = sbrk(trimSz) + trimSz;
		leftSize += trimSz;
	}
	void* newAlloc = allocStartPtr;
	allocStartPtr += size;
	leftSize -= size;
	return newAlloc;
}

void* allocFromFast(size_t index){
	BLK* newAllocPtr = fastBins[idx]; 
	fastBins[idx] = fastBins[idx].next;
	debug ("  alloc fastBins[%d] : %u ", index, newAllocPtr); 
	return newAllocPtr; 
}


void* allocFromSmall(size_t index){
	BLK* newAllocPtr = smallBins[idx]; 
	smallBins[idx] = smallBins[idx].next; 
	debug("  alloc smallBins[%d] : %u ", index, newAllocPtr); 
	return newAllocPtr + BLK_HEADER_SZ; 
}

void dumpFast(size_t index){
	debug("fastBins[%d] : ", index); 
	BLK* next = fastBins[index]; 
	while(next != EMPTY){
		debug("%p -> ", fastBins[index]->next); 
		next = fastBins[index]->next; 
	}
	debug("END\n"); 
	return; 
}


void *myalloc(size_t size)
{
	debug("= [myalloc start] ====================================="); 
	for(int i = 0; i < F_BIN_COUNT; i++) 
		dumpFast(i);
	dubug("\n"); 

	size += BLK_HEADER_SZ; 
	void* newAllocPtr; 

	if(size < F_BIN_START_SZ) 
		size = F_BIN_START_SZ; 	
	size = F_TRIM_SZ(size); 
	
	debug("  final trimed size : %d\n", size); 
	if(size < S_BIN_START_SZ) { //allocate fast bin! 
		size_t idx = F_SZ_2_IDX(size);
		if(fastBins[idx] != EMPTY)
			newAllocPtr =  allocFromFast(idx); 
	}
	/*else if(size < L_BIN_SZ) { //allocate small bin; 
		size_t idx = S_SZ_2_IDX(size); 
		if(smallBins[idx] != EMPTY) 
		return allocFromSmall(idx); 
	}
	else{ //allocate large bin; 
	
	}*/ 
	
	//allocate new 
	else{ 
		newAllocPtr = myInternalSbrk(size); 
	}
	*(size_t*)(newAllocPtr + BLK_SZ_IDX) = size; 
    *(size_t*)(newAllocPtr + size + BLK_SZ_IDX) = size|0x1;
	debug ("= [myalloc finished] ======================================"); 
    return newAllocPtr + BLK_HEADER_SZ;
}


void *myrealloc(void *ptr, size_t size)
{
    void *p = NULL;
    if (size != 0)
    {
        p = myInternalSbrk(size);
        if (ptr)
            memcpy(p, ptr, size);
       // max_size += size;
        debug("max: %u\n", max_size);
    }
    debug("realloc(%p, %u): %p\n", ptr, (unsigned int)size, p);
    return p;
}


void insertFastBins(size_t index, void* startBlock){
	if(fastBins[index] != EMPTY) {
		startBlock->next = fastBins[index].next; 
	}
	fastbins[index] = startBlock; 
	//startBlock + F_IDX_2_SIZE(index) + F_SZ_IDX)	
}


void myfree(void *ptr){
	void** prevSizePtr = ptr - BLK_HEADER_SZ; 
	size_t size = *(size_t*)(prevSizePtr + BLK_SZ_IDX); 
	if(size < F_BIN_START_SZ ) 
		error("in myfree(), too small chunk, this size is not possible!"); 
    else if(size < S_BIN_START_SZ) {//fast bins 
		insertFastBins(F_SZ_2_IDX(size)); 
	}

	(size_t*)(prevSizePtr + size  + BLK_SZ_IDX) = size&0xfffffffffffffffe; 
	debug("free(%p)\n", ptr);
	return; 
}



