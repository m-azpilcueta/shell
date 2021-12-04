#ifndef SHELL_PROCLIST_H
#define SHELL_PROCLIST_H

#include <stdlib.h>
#include <stdio.h>

typedef struct {
    pid_t pid;
    int priority;
    char user[256];
    char command[128];
    time_t time;
    char state[50];
    int returned_value;
} data;

struct Node {
    struct Node * previous;
    data values;
    struct Node * next;
};

int appendProc(struct Node ** head, data values);
void clearProcList(struct Node ** head);
#endif //SHELL_PROCLIST_H
