#include <assert.h>
#include <stdlib.h>
#include <algorithm>
#include <atomic>
#include <cstring>  // for memset
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>



#include "Enclave_t.h"  // structs defined in .edl file etc
#include <sgx_trts.h>  // trusted runtime system, usually always required


#define NODE_SIZE 256


struct Node {
   Node* next{nullptr};
   uint64_t data{0};     // just to ensure that it will not be outcompiled
   uint64_t padding[(NODE_SIZE-8-8)/8];  // (64 -8-8)/8 (8 is lengtho of uint64)
}__attribute__ ((aligned (NODE_SIZE)));




thread_local Node* root;
thread_local Node* node;
int tid;


Node* allocateList(uint64_t number_nodes);
void freeList(Node* root);
uint64_t rnd(uint64_t& seed);
void random_shuffle(std::vector<uint64_t>& nodes_idxs);
void shuffleList(Node*& root, uint64_t number_nodes, bool shuffle);
void printf(const char *fmt, ...);





//Ecalls
void preallocate_ecall(uint64_t* number_nodes, int* rnd){



   root = allocateList(*number_nodes);
   
   if (root == NULL){
      printf("Memory allocation inside enclave failed. \n");
   }
    
   node = root;

   uint64_t n = ((uintptr_t)node) % NODE_SIZE;

   if (n != 0) {
      char* p = (char*)node;
      p = p + (NODE_SIZE - n);
      node = (Node*)p;
   }

   if (((uintptr_t)node) % 64 != 0) {
      throw std::logic_error("Not CL aligned " + std::to_string(((uintptr_t)node) % 64));
   }

   shuffleList(node, *number_nodes, *rnd);

}


void custom_ecall(uint64_t* result){

    *result = 0;
    auto* current = node;
    uint64_t counter = 0;

    if (current == NULL)
        printf("No Allocation was done .\n");


    while (current) {
        *result += current->data;
        current = current->next;
        counter++;
        }


      *result = counter;
   }


   void empty_ecall(){
      return ;
   }





////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


Node* allocateList(uint64_t number_nodes)
{
   if (sizeof(Node) != NODE_SIZE) {
      throw std::logic_error("Node size wrong" + std::to_string(sizeof(Node)));
   }
   Node* node = new Node[number_nodes + 1];

   return node;
}

void freeList(Node* root)
{
   delete[] root;
}

uint64_t rnd(uint64_t& seed)
{
   uint64_t x = seed;
   x ^= x >> 12;      // a
   x ^= x << 25;      // b
   x ^= x >> 27;      // c
   seed = x;
   return x * 0x2545F4914F6CDD1D;
}

void random_shuffle(std::vector<uint64_t>& nodes_idxs)
{
   auto n = nodes_idxs.size();
   uint64_t seed = 19650218ULL;
   for (uint64_t i = n - 1; i > 0; --i) {
      std::swap(nodes_idxs[i], nodes_idxs[rnd(seed) % (i + 1)]);
   }
}

void shuffleList(Node*& root, uint64_t number_nodes, bool shuffle)
{
   // -------------------------------------------------------------------------------------
   // create help vector of idx
   std::vector<uint64_t> node_idxs(number_nodes - 1);  // one less because we do not start at 0 -> root should stay root
   std::iota(std::begin(node_idxs), std::end(node_idxs), 1);
   if (shuffle)
      random_shuffle(node_idxs);
   // -------------------------------------------------------------------------------------
   uint64_t counter = 0;
   auto* prev = root;
   for (auto& idx : node_idxs) {
      prev->next = &root[idx];
      prev->data = counter++;
      prev = prev->next;
   }
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}