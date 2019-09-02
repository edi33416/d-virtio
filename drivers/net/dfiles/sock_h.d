
struct sockaddr {
    sa_family_t sa_family; /* address family, AF_xxx	*/
    char[14] sa_data; /* 14 bytes of protocol address	*/
};

alias __kernel_sa_family_t = ushort;
alias sa_family_t = __kernel_sa_family_t;
