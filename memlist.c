/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include "memlist.h"

void createEmptyMemlist(tMemList* list) {
    list->last = -1;
}

int insertNode(Node node, tMemList* list) {
    if (list->last == MAX_MEML - 1) {
        return 0;
    } else {
        Node *insert = (Node*) malloc(sizeof(node));
        if (insert == NULL) {
            printf("Could not allocate memory\n");
            return 0;
        } else {
            *insert = node;
            list->last++;
            list->node[list->last] = insert;
            return 1;
        }
    }
}

int checkNode(Node position, Node remove) {
    if (strcmp(position.alloc_type, "malloc") == 0) {
        if (position.size == remove.size) return 1;
    } else if (strcmp(position.alloc_type, "shared") == 0) {
        if (strcmp(position.name, remove.name) == 0) return 1;
    } else if (strcmp(position.alloc_type, "mapped") == 0) {
        if (position.key == remove.key) return 1;
    } else if (position.address == remove.address) return 1;
    return 0;
}

int removeNode(Node node, tMemList* list) {
    int exists, found = 0;
    if (list->last == -1) return 0;
    else {
        for (int i = 0; i <= list->last; i++) {
            if (!found) {
                exists = checkNode(node, *list->node[i]);
                if (exists) {
                    Node* tmp = list->node[i];
                    free(tmp);
                    found = 1;
                }
            }
            if (found) {
                list->node[i] = list->node[i+1];
            }
        }
        if (found) {
            list->last--;
            return 1;
        }
        return 0;
    }
}

void deleteMemlist(tMemList* list) {
    for (int i = 0; i <= list->last; i++) {
        if (strcmp(list->node[i]->alloc_type, "malloc") == 0) free(list->node[i]->address);
        free(list->node[i]);
    }
    list->last = -1;
}

void nodeInfo(Node node) {
    struct tm *info;
    char buffer[50];
    info = localtime(&node.time);
    strftime(buffer,sizeof(buffer),"%c",info);

    if (strcmp(node.alloc_type, "malloc") == 0) {
        printf("%20p size: %20lu %14s %s\n", node.address, node.size, node.alloc_type, buffer);
    } else if (strcmp(node.alloc_type, "shared memory") == 0) {
        printf("%20p size: %20lu %14s (key %d) %s\n", node.address, node.size, node.alloc_type, node.key, buffer);
    } else if (strcmp(node.alloc_type, "mapped file") == 0) {
        printf("%20p size: %20lu %14s %s (fd: %d) %s\n", node.address, node.size, node.alloc_type, node.name, node.key, buffer);
    }
}

void showNodes(tMemList list, char *alloc_type) {
    if (list.last == -1) {
        printf("Block list is empty\n");
        return;
    }
    for (int i = 0; i <= list.last; i++) {
        if (strcmp(list.node[i]->alloc_type, alloc_type) == 0 || strcmp(alloc_type, "-all") == 0) {
            nodeInfo(*list.node[i]);
        }
    }
}

Node* findNodeBySize(size_t size, char *alloc_type, tMemList list) {
    for (int i = 0; i <= list.last; i++) {
        if (strcmp(alloc_type, list.node[i]->alloc_type) == 0) {
            if (size == list.node[i]->size) {
                return list.node[i];
            }
        }
    }
    return NULL;
}

Node* findNodeByName(char* name, char *alloc_type, tMemList list) {
    for (int i = 0; i <= list.last; i++) {
        if (strcmp(alloc_type, list.node[i]->alloc_type) == 0) {
            if (strcmp(name, list.node[i]->name) == 0) {
                return list.node[i];
            }
        }
    }
    return NULL;
}

Node* findNodeByKey(key_t key, char *alloc_type, tMemList list) {
    for (int i = 0; i <= list.last; i++) {
        if (strcmp(alloc_type, list.node[i]->alloc_type) == 0) {
            if (key == list.node[i]->key) {
                return list.node[i];
            }
        }
    }
    return NULL;
}

Node* findNodeByAddress(char *address, tMemList list) {
    void *addr = (void *) strtoul(address, NULL, 16);
    for (int i = 0; i <= list.last; i++) {
        if (addr == list.node[i]->address)
            return list.node[i];
    }
    return NULL;
}
