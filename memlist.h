#ifndef SHELL_MEMLIST_H
#define SHELL_MEMLIST_H
#define MAX_MEML 4096

#include <time.h>
#include <sys/shm.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef int tPos;

typedef struct {
    char name[1024];
    char alloc_type[50];
    void *address;
    size_t size;
    time_t time;
    key_t key;
} Node;

typedef struct {
    Node *node[MAX_MEML];
    tPos last;
} tMemList;

void createEmptyMemlist(tMemList* list);
int insertNode(Node node, tMemList* list);
int removeNode(Node node, tMemList* list);
void deleteMemlist(tMemList* list);
void showNodes(tMemList list, char* alloc_type);
Node* findNodeBySize(size_t size, char *alloc_type, tMemList list);
Node* findNodeByName(char* name, char *alloc_type, tMemList list);
Node* findNodeByKey(key_t key, char *alloc_type, tMemList list);
#endif //SHELL_MEMLIST_H
