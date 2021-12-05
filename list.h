#ifndef LIST_H
#define LIST_H
#define MAX_L 4096

#include <string.h>
#include <stdio.h>

typedef int tPos;
typedef struct {
    char *data[MAX_L];
    tPos last;
} tHist;

void createEmptyHistory(tHist* h);
int isEmptyHistory(tHist h);
int isFullHistory(tHist h);
int insertHistory(char* data, tHist* h);
tPos findHistory(char* data, tHist h);
char* getHistory(tPos pos, tHist h);
void deleteHistory(tHist* h);   
void showHistory(tHist h);
void showNHistory(tPos n, tHist h);

#endif