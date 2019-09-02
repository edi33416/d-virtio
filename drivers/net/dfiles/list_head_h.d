struct list_head {
    list_head* next, prev;
}

struct hlist_head {
    hlist_node *first;
};

struct hlist_node {
    hlist_node *next;
    hlist_node **pprev;
};


