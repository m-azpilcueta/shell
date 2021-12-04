/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include "proclist.h"

int appendProc(struct Node ** head, data values) {
    struct Node * insert = (struct Node *) malloc(sizeof(struct Node));
    struct Node * last = *head;
    if (insert == NULL) {
        printf("Could not allocate memory\n");
        return 0;
    } else {
        insert->values = values;
        insert->next = NULL;
        if (*head == NULL) {
            insert->previous = NULL;
            *head = insert;
            return 1;
        }
        while(last->next != NULL) {
            last = last->next;
        }
        last->next = insert;
        insert->previous = last;
        return 1;
    }
}

void clearProcList(struct Node ** head) {
    if (*head == NULL) return;
    else {
        struct Node *it = *head;
        while(it != NULL) {
            struct Node *tmp = it;
            it = it->next;
            *head = it;
            free(tmp);
        }
    }
}
