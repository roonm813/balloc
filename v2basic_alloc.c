#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

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

#define tdebug //
//#define tdebug debug 
#define mdebug //debug
//#define mdebug debug
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
long long unsortMaxSize = 0; 

uint8_t leftSize; 
void* allocStartPtr; 
void* allocBackupPtr; 
uint8_t setting = 0; 


inline void initSet(){
	allocStartPtr = sbrk(PAGE_SZ);
	allocBackupPtr = allocStartPtr + PAGE_SZ;
   	leftSize = PAGE_SZ;
	return;
}


void error(const char * errmsg){
	debug("ERROR! %s\n", errmsg);
	abort(); 
}


inline void* myInternalSbrk(size_t size){
	if(!setting){
		initSet();
	  	setting = 1;
	}
	if(leftSize <= size + sizeof(size_t)) {
		size_t trimSz = PAGE_TRIM_SZ(size);
		allocBackupPtr = sbrk(trimSz) + trimSz;
		leftSize += trimSz;
	}
	void* newAlloc = allocStartPtr;
	allocStartPtr += size;
	leftSize -= size;
	return newAlloc;
}

inline void* allocFromFast(size_t index){
	BLK* newAllocPtr = fastBins[index]; 
	fastBins[index] = fastBins[index]->next;

	int size = F_IDX_2_SZ(index);
	setBlockSize(newAllocPtr, size, 1); 
//	newAllocPtr->size = siz; 
//	*(size_t*)(((void*)newAllocPtr)+F_IDX_2_SZ(index)) = size|0x1; 
	mdebug ("  alloc fastBins[%d] \t: 0x%p\n", index, newAllocPtr); 
	return (void*)newAllocPtr; 
}


void* allocFromSmall(size_t index){
	BLK* newAllocPtr = smallBins[index]; 
	smallBins[index] = smallBins[index]->next; 
	debug("  alloc smallBins[%d] : %u \n", index, newAllocPtr); 
	return newAllocPtr + BLK_HEADER_SZ; 
}

inline void unlink(BLK* block){
	//debug ("  unlink block at 0x%x\n", block); 
	//dumpChunk(block);*/ 
	if(block == unsortedBins && block == unsortedBinsEnd){
		unsortedBins = (unsortedBinsEnd = EMPTY); 
	}
	else if(block == unsortedBins) {
		unsortedBins = block->next;
		unsortedBins->prev = EMPTY; 
	}
	else if(block == unsortedBinsEnd){
		unsortedBinsEnd = block->prev; 
		unsortedBinsEnd->next = EMPTY;
		//block->prev->next = EMPTY; 
		//unsortedBinsEnd = block->prev; 
	}
	else{
		block->prev->next = block->next; 
		block->next->prev = block->prev; 
	}
	//debug("  [+](in unlink)"); dumpUnsorted(); 
	return; 
}

inline void setBlockSize(BLK* block, size_t size, int inUsed){
	block->size = size;
	if(inUsed){ 
		*(size_t*)(((void*)block) + size) = size|0x1; 
	}
	else 
		*(size_t*)(((void*)block) + size) = size&0xfffffffffffffffe; 
	return; 
}

void* allocFromUnsorted(size_t size){
	debug("  alloc from Unsorted bins\n"); 
	clock_t before; 
	before = clock(); 
	//debug("  start unsorted bins 0x%x\n", unsortedBins); 
	//debug("  end unsorted bins   0x%x\n", unsortedBinsEnd); 
	//debug("  [+]"); dumpUnsorted(); 
	//mdebug("  [+]"); dumpReverseUnsorted(); 
	BLK* here = unsortedBinsEnd;
	
	//if(unsortedBins!=EMPTY){debug("start !!"); dumpChunk(unsortedBins);} 
	void* newAllocPtr; 
	size_t totalSize;
	BLK* leftPtr; 
	size_t leftSize; 
	int count = 0; 	
	while(here != EMPTY){
		if((here->size) >= size){
		//	dumpChunk(here); 
			newAllocPtr = here; 
			totalSize = here->size; 
			leftPtr = (void*)here + size; 
			leftSize = totalSize - size; 
			break; 
		}
		count ++; 
		here = here->prev; 
		if(count > 200) {
		// 	debug("adsfasdfasf"); 
			here = EMPTY; 
			break; 
		}
	}
	//debug("out asdf : 0x%x\n", here); 
	if(here ==  EMPTY) {
		debug("  => nothing is in unsorted \n"); 
		tdebug("  time : %f\n", (double)(clock()-before)); 
		return EMPTY; 
	}
	else if(leftSize < F_BIN_START_SZ){
		debug("  => find one! but left size is so small, so just give all\n"); 
		unlink(newAllocPtr); 
		*(size_t*)(newAllocPtr + totalSize) = size|0x1; 
		//mdebug ("  [+]"); dumpUnsorted(); 
		tdebug("  time : %f\n", (double)(clock()-before)); 
		return newAllocPtr; 
	}
	else if(leftSize < S_BIN_START_SZ){ //split to fast bin 

		debug("  => find one! and tryiny to split -> fastbins\n"); 
		/*if(newAllocPtr == unsortedBinsEnd){
			
		}*/ 
		setBlockSize(newAllocPtr, size, 1); 
		setBlockSize(leftPtr, leftSize, 0); 
		unlink(newAllocPtr); 
		insertFastBins(F_SZ_2_IDX(leftSize), leftPtr); 
		tdebug("  time : %f\n", (double)(clock()-before)); 
		//mdebug("  [+] "); dumpUnsorted(); 
		return newAllocPtr; 
	}
	else{//just split 
		debug("  => just split -> unsorted\n"); 
	//	unlink(newAllocPtr);
		setBlockSize(newAllocPtr, size, 1); 
		setBlockSize(leftPtr, leftSize, 0);
		leftPtr->next = ((BLK*)newAllocPtr)->next; 
		leftPtr->prev = newAllocPtr; 
		((BLK*)newAllocPtr)->next = leftPtr;

		if(leftPtr->next != EMPTY) leftPtr->next->prev = leftPtr; 
		if(newAllocPtr == unsortedBinsEnd) unsortedBinsEnd = leftPtr; 	
		unlink(newAllocPtr); 
		tdebug("  time : %f\n", (double)(clock()-before)); 
		return newAllocPtr; 
	}
		tdebug("  time : %f\n", (double)(clock()-before)); 
	return EMPTY;
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

void dumpReverseUnsorted(){
	debug("unosorted Bins Reverse : "); 
	BLK* here = unsortedBinsEnd; 
	while(here != EMPTY){
		debug("0x%x(0x%x) -> " , here, here->size); 
		here = here -> prev; 
	}
	debug("END\n"); 
	return ;
}

void dumpUnsorted(){
	debug ("unsorted Bins : "); 
	BLK* here = unsortedBins; 
	while(here != EMPTY){
		debug ("0x%x(0x%x) -> ", here, here->size); 
		here = (here -> next); 
	}
	debug("END\n"); 
	return; 
}


void dumpChunk(BLK* ptr){
	debug("[+] dumpChunk at 0x%x -----------------\n", ptr); 
	debug("  prevSize :\t 0x%x\n", ptr->prevSize);
	debug("  size :    \t 0x%x\n", ptr->size); 
	debug("  prev :    \t 0x%p\n", ptr->prev); 
	debug("  next :    \t 0x%p\n", ptr->next); 
	debug("---------------------------------------\n"); 
}


void *myalloc(size_t size)
{
	debug("= [myalloc start] size = 0x%x ==============================\n", size); 

	size += BLK_HEADER_SZ; 
	void* newAllocPtr; 

	if(size < F_BIN_START_SZ) {
		size = F_BIN_START_SZ; 
		debug("  size is small than minimal size\n"); 	
	}
	size = F_TRIM_SZ(size); 

	debug("  final trimed size : 0x%x\n", size); 
	if(size < S_BIN_START_SZ && fastBins[F_SZ_2_IDX(size)]!= EMPTY) { //allocate fast bin! 
		size_t idx = F_SZ_2_IDX(size);
		debug("  fastbin index is [%d]\n", idx); 
		debug("  fastbin is not empty, goto fastbin now\n"); 
		newAllocPtr =  allocFromFast(idx);
	}
	else if((unsortMaxSize < size) || ((newAllocPtr = allocFromUnsorted(size)) == EMPTY)){ //allocate from top chunk 
		newAllocPtr = myInternalSbrk(size); 
		setBlockSize(newAllocPtr, size, 1); 
	}
	debug ("========================================================\n\n"); 
	
	return newAllocPtr + BLK_HEADER_SZ;
}


void *myrealloc(void *ptr, size_t size)
{ 	debug("= [myrealloc started] ===================================\n");
	void *p = NULL;
    if (size != 0)
    {
        p = myalloc(size);
        if (ptr != EMPTY)
            memcpy(p, ptr, size);
    }
    debug("realloc(0x%x, 0x%x) =>  0x%x\n", ptr, (unsigned int)size, p);
	debug("========================================================\n\n"); 
    return p;
}


inline void insertFastBins(size_t index, BLK* startBlock){
	debug("  insert into fastBins[%d]_size(0x%x)\n", index, F_IDX_2_SZ(index)); 
	if(fastBins[index] != EMPTY) {
		startBlock->next = fastBins[index]; 
	}
	else 
		startBlock->next = EMPTY; 
	fastBins[index] = startBlock; 
}


inline void insertUnsortedBins(size_t size, BLK* startBlock){
	debug("  insert into UnsortedBins size(0x%x) ptr(0x%p)\n", size, startBlock); 
	if(unsortMaxSize < size) 
		unsortMaxSize = size; 
	if(unsortedBins != EMPTY){ //not first Insert; 
		startBlock->next = unsortedBins; 
		unsortedBins->prev = startBlock; 
	}
	else {//fisrt insert 
		mdebug("  WELCOME! unsortedBIns firstinput\n"); 
		unsortedBinsEnd = startBlock; 
		startBlock->next = EMPTY; 
	}
	unsortedBins = startBlock; 
	unsortedBins->prev = EMPTY; 
	return; 
}


void myfree(void *ptr){
	debug("= [myfree started] in 0x%x===============================\n", ptr); 
	if(ptr == NULL){
		debug("nullptr just return it!\n\n"); 
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
	debug("======================================================\n\n"); 
	return; 
}

