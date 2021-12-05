/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include "list.h"
#include <stdlib.h>

void createEmptyHistory(tHist* h) {
        h->last = -1;
}

int isEmptyHistory(tHist h) {
    return h.last == -1;
}

int isFullHistory(tHist h) {
    return h.last == MAX_L - 1;
}

int insertHistory(char* data, tHist* h) {
   if(isFullHistory(*h)) 
        return 0;
    else {
        h->last++;
        h->data[h->last] = strdup(data);
        return 1;
    }   
}

tPos findHistory(char* data, tHist h) {
    tPos i;
    
    if(isEmptyHistory(h)) 
        return -1;
    else {
        for (i = 0; (i < h.last) && (strcmp(h.data[i],data) != 0) ; i++);
        if(strcmp(h.data[i], data) == 0)
            return i;
        else return -1; 
    }  
}

char* getHistory(tPos pos, tHist h) {
    return h.data[pos];
}

void deleteHistory(tHist* h) {
    for (int i = 0; i <= h->last; i++) {
        free(h->data[i]);
    }
    h->last = -1;
}

void showHistory(tHist h) {
    for (int i = 0; i <= h.last; i++) {
        printf("%d -> %s", i, h.data[i]);
    }  
}

void showNHistory(tPos n, tHist h) {
    for (int i = 0; i < n; i++) {
        printf("%d -> %s", i, h.data[i]);
    }
}
