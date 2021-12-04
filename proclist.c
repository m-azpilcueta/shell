/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include "proclist.h"

void createProcList(tProcList* list) {
    list->last = -1;
}

int insertProc(data proc, tProcList* list) {
    if (list->last == MAX_PROCL - 1) return 0;
    else {
        data * insert = (data *) malloc(sizeof(data));
        if (insert == NULL) {
            printf("Could not allocate memory\n");
            return 0;
        } else {
            *insert = proc;
            list->last++;
            list->data[list->last] = insert;
            return 1;
        }
    }
}

void clearProcList(tProcList* list) {
    for (int i = 0; i <= list->last; i++) {
        free(list->data[i]);
    }
    list->last = -1;
}