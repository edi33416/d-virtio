static if(is(typeof(__GLIBC__)))
{
    enum isDefined(alias e) = is(typeof(e));

    static if(is(typeof(_NET_IF_H)) && is(typeof(__USE_MISC))) {
        enum __UAPI_DEF_IF_IFNAMSIZ = 0;
    }
    else {
        enum __UAPI_DEF_IF_IFNAMSIZ = 1;
    }

}
else
{
    static if (!is(typeof(__UAPI_DEF_IF_IFNAMSIZ)))
        enum __UAPI_DEF_IF_IFNAMSIZ = 1;


}

static if(is(typeof(__UAPI_DEF_IF_IFNAMSIZ)))
{
    enum IFNAMSIZ = 16;
}

