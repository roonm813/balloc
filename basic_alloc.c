#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

typedef struct block{
	size_t prevSize; 
	size_t size; 
	
	struct block* prev; 
	struct block* next; 
}__attribute__((packed)) BLK; 

#define BLK_PREV_SZ_IDX 0 
#define BLK_SZ_IDX 8 
#define BLK_PREV_IDX 16 
#define BLK_NEXT_IDX 24 

//#define mdebug //debug 
#define mdebug debug
#define debug //debug
#define PAGE_TRIM_SZ(size) (((size)%(PAGE_SZ)) ? (((size)&(0xfffffffffffff000)) + PAGE_SZ) : (size))

#define PAGE_SZ 0x1000
#define BLK_HEADER_SZ 0x10 
#define EMPTY NULL

#define F_BIN_START_SZ 0x20 
#define F_BIN_COUNT 7
#define F_BIN_INTERVAL 0x10 

#define S_BIN_START_SZ 0x90 
#define S_BIN_COUNT 50 
#define S_BIN_INERVAL 0x10 

#define L_BINS_SZ 0x410 

#define F_IDX_2_SZ(idx) (F_BIN_START_SZ + (idx)*F_BIN_INTERVAL) 
#define F_SZ_2_IDX(size) ((size - F_BIN_START_SZ + 1) / F_BIN_INTERVAL)  
#define F_TRIM_SZ(size) (((size)%(F_BIN_INTERVAL))?(((size)&(0xfffffffffffffff0)) + F_BIN_INTERVAL): (size)) 

#define S_IDX_2_SZ(idx) (S_BIN_START_SZ + (idx)*S_BIN_INTERVAL) 
#define S_SZ_2_IDX(size) ((size - S_BIN_START_SZ + 1) / S_BIN_INTERVAL)  
#define S_TRIM_SZ(size) (((size)%(S_BIN_INTERVAL))?(((size)&(0xfffffffffffffff0)) + S_BIN_INTERVAL): (size)) 

BLK* fastBins[F_BIN_COUNT] = {EMPTY, EMPTY, }; 
BLK* smallBins[S_BIN_COUNT] = {EMPTY, EMPTY, }; 
BLK* largeBins = EMPTY;  

BLK* unsortedBins = EMPTY; 
BLK* unsortedBinsEnd = EMPTY; 

uint8_t leftSize; 
void* allocStartPtr; 
void* allocBackupPtr; 
uint8_t setting = 0; 

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
/*void* myInternalSbrk(size_t size) {
	//debug("alloc \t\t 0x%x", size); 
	return sbrk(size + 8); 
}*/

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
//	for(int i=0; i<F_BIN_COUNT; i++) 
//		dumpFast(i); 
	BLK* newAllocPtr = fastBins[index]; 
	fastBins[index] = fastBins[index]->next;
	mdebug ("  alloc fastBins[%d] \t: 0x%p\n", index, newAllocPtr); 
	return newAllocPtr; 
}


void* allocFromSmall(size_t index){
	BLK* newAllocPtr = smallBins[index]; 
	smallBins[index] = smallBins[index]->next; 
	debug("  alloc smallBins[%d] : %u \n", index, newAllocPtr); 
	return newAllocPtr + BLK_HEADER_SZ; 
}

void dumpFast(size_t index){
	debug("fastBins[%d]_size(0x%x) : ", index, F_IDX_2_SZ(index)); 
	BLK* here = fastBins[index]; 
	while(here != EMPTY){
		debug("%p -> ", here); 
		here = here->next; 
	}
	debug("END\n"); 
	return; 
}

void dumpUnsorted(){
	debug ("unsorted Bins : "); 
	BLK* here = unsortedBins; 
	while(here != EMPTY){
		debug ("%p -> ", here); 
		here = here -> next; 
	}
	return; 
}

void dumpChunk(void* ptr){
	mdebug("[+] dumpChunk at 0x%x -----------------\n", ptr); 
	mdebug("  prevSize :\t 0x%x\n", *(size_t*) (ptr + BLK_PREV_SZ_IDX));
	mdebug("  size :    \t 0x%x\n", *(size_t*) (ptr+ BLK_SZ_IDX)); 
	mdebug("  prev :    \t 0x%p\n", ptr + BLK_PREV_IDX); 
	mdebug("  next :    \t 0x%p\n", ptr + BLK_NEXT_IDX); 
	mdebug("---------------------------------------\n"); 
}


void *myalloc(size_t size)
{
	mdebug("= [myalloc start] size = 0x%x ==============================\n", size); 
	//for(int i=0; i<F_BIN_COUNT; i++) 
	//	dumpFast(i); 

	size += BLK_HEADER_SZ; 
	void* newAllocPtr; 

	if(size < F_BIN_START_SZ) {
		size = F_BIN_START_SZ; 
		mdebug("  size is small than minimal size\n"); 	
	}
	size = F_TRIM_SZ(size); 

	mdebug("  final trimed size : 0x%x\n", size); 
	if(size < S_BIN_START_SZ && fastBins[F_SZ_2_IDX(size)]!= EMPTY) { //allocate fast bin! 
		size_t idx = F_SZ_2_IDX(size);
		mdebug("  fastbin index is [%d]\n", idx); 
		mdebug("  fastbin is not empty, goto fastbin now\n"); 
		newAllocPtr =  allocFromFast(idx);
	}
	else{
		mdebug("  malloc from top chunk\n"); 
		newAllocPtr = myInternalSbrk(size); 
		mdebug("  alloc in    \t 0x%p\n", newAllocPtr + BLK_HEADER_SZ); 
	}
	*(size_t*)(newAllocPtr + BLK_SZ_IDX) = size; 
	*(size_t*)(newAllocPtr + size ) = size|0x1;
	mdebug ( "  set prevSize\t*0x%p = 0x%x\n", newAllocPtr + BLK_SZ_IDX, size); 
	mdebug ( "  set size    \t*0x%p = 0x%x\n", newAllocPtr + size, size|0x1); 
	mdebug ("========================================================\n\n"); 
	
	return newAllocPtr + BLK_HEADER_SZ;
}


void *myrealloc(void *ptr, size_t size)
{ 	mdebug("= [myrealloc started] ===================================\n"); 
    void *p = NULL;
    if (size != 0)
    {
        p = myInternalSbrk(size);
        if (ptr)
            memcpy(p, ptr, size);
       // max_size += size;
        //debug("max: %u\n", max_size);
    }
    mdebug("realloc(%p, %u): %p\n", ptr, (unsigned int)size, p);
	mdebug("========================================================\n\n"); 
    return p;
}


void insertFastBins(size_t index, BLK* startBlock){
	//for(int i = 0; i < F_BIN_COUNT; i++) 
	//	dumpFast(i); 
	mdebug("  insert into fastBins[%d]_size(0x%x)\n", index, F_IDX_2_SZ(index)); 
	dumpChunk(startBlock); 
	if(fastBins[index] != EMPTY) {
		startBlock->next = fastBins[index]->next; 
	}
	else 
		startBlock->next = EMPTY; 
	fastBins[index] = startBlock; 
}

void insertUnsortedBins(size_t size, BLK* startBlock){
	mdebug("  insert into UnsortedBins size(0x%x) ptr(0x%p)\n", size, startBlock); 
	dumpChunk(startBlock); 
	if(unsortedBins != EMPTY){ //not first Insert; 
		startBlock->next = unsortedBins->next; 
	}
	else {//fisrt insert 
		unsortedBins_end = startBlock; 
		startBlock->next = EMPTY; 
	}
	unsortedBins = startBlock; 
	//need merging process 
	return; 
}

void myfree(void *ptr){
	mdebug("= [myfree started] in 0x%x===============================\n", ptr); 
	if(ptr == NULL){
		mdebug("nullptr just return it!\n\n"); 
		return; 
	}
	void* prevSizePtr = ptr - BLK_HEADER_SZ;
	size_t prevSize = *(size_t*)prevSizePtr; 
	size_t size = *(size_t*)(prevSizePtr + BLK_SZ_IDX); 
	*(size_t*)(prevSizePtr + size) = size&0xfffffffffffffffe; 
	mdebug("  header Start ptr\t 0x%p\n", prevSizePtr); 
	mdebug("  prev chunk size \t*0x%p = 0x%x\n",  prevSizePtr,  prevSize); 
	mdebug("  this chunk size \t*0x%p = 0x%x\n", prevSizePtr + BLK_SZ_IDX, size); 
	if(size < F_BIN_START_SZ ) 
		error("in myfree(), too small chunk, this size is not possible!"); 
    else if(size < S_BIN_START_SZ) {//fast bins 
		insertFastBins(F_SZ_2_IDX(size), prevSizePtr); 
	}
	else{ //unsorted bin
		insertUnsortedBins(size, prevSizePtr); 
	}
	mdebug("======================================================\n\n"); 
	return; 
}

