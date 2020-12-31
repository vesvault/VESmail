
typedef struct jTree {
    void *data;
    void *extra;
    struct jTree *left;
    struct jTree *right;
    struct jTree *back;
    unsigned char ldepth;
    unsigned char rdepth;
} jTree;

#define jTree_new()	NULL
void **jTree_seek(struct jTree **ptree, void *term, void *arg, int (* cmpfn)(void *data, void *term, void *arg), unsigned char *depth);
void **jTree_first(struct jTree *jtree);
void **jTree_last(struct jTree *jtree);
void **jTree_next(void **pdata);
void **jTree_prev(void **pdata);

int jTree_walk(struct jTree *jtree, void *arg, int (* walkfn)(void **pdata, void *arg));
int jTree_rwalk(struct jTree *jtree, void *arg, int (* walkfn)(void **pdata, void *arg));
unsigned char jTree_collapse(struct jTree **ptree);
