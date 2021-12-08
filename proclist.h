#ifndef SHELL_PROCLIST_H
#define SHELL_PROCLIST_H

#define MAX_PROCL 4096

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>

#include <signal.h>

typedef int tPos;

typedef struct {
    pid_t pid;
    int priority;
    char user[256];
    char command[128];
    time_t time;
    char state[50];
    int returned_value;
} data;

typedef struct {
    data *data[MAX_PROCL];
    tPos last;
} tProcList;

void createProcList(tProcList *list);
int insertProc(data proc, tProcList *list);
int findProc(pid_t pid, tProcList list);
data* getProc(tPos pos, tProcList list);
int removeProcByPid(pid_t pid, tProcList* list);
void clearProcList(tProcList *list);
void updateProcList(tProcList *list);
void printProc(data proc);
void showProcList(tProcList list);
char * NombreSenal(int sen);

#endif //SHELL_PROCLIST_H
