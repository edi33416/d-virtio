import core.stdc.config;
import virtio_h;
import mod_devicetable_h;
import napi_struct_h : napi_struct;
import spinlock_types_h;
import device_h;
import mutex_h;
import kobject_h : kobject;
import net_device_h;

pragma(msg, "Sizeof napi_struct: ", napi_struct.sizeof);
pragma(msg, "Sizeof virtqueue: ", virtqueue.sizeof);
pragma(msg, "Sizeof virtio_device: ", virtio_device.sizeof);
pragma(msg, "Sizeof bool: ", bool.sizeof);
pragma(msg, "Sizeof spinlock_t:", spinlock_t.sizeof);
pragma(msg, "Sizeof device:", device.sizeof);
pragma(msg, "Sizeof virtio-device_id:", virtio_device_id.sizeof);
pragma(msg, "Sizeof mutex:", mutex.sizeof);
pragma(msg, "Sizeof kobject:", kobject.sizeof);
pragma(msg, "Sizeof dev_links_info :", dev_links_info.sizeof);
pragma(msg, "Sizeof dev_pm_info:", dev_pm_info.sizeof);
pragma(msg, "Sizeof dev_archdata:", dev_archdata.sizeof);
pragma(msg, "Sizeof klist_node:", klist_node.sizeof);
pragma(msg, "Sizeof net_device:", net_device.sizeof);
pragma(msg, "Sizeof netdev_tc_txq:", netdev_tc_txq.sizeof);
pragma(msg, "Sizeof possible_net_t:", possible_net_t.sizeof);
pragma(msg, "Sizeof netdev_hw_addr_list:", netdev_hw_addr_list.sizeof);
pragma(msg, "Sizeof atomic_t:", atomic_t.sizeof);
pragma(msg, "Sizeof atomic_long_t:", atomic_long_t.sizeof);
pragma(msg, "Sizeof timer_list:", timer_list.sizeof);
pragma(msg, "Sizeof net_device_stats:", net_device_stats.sizeof);



extern(C) int txq2vq(int txq) {
    return txq * 2 + 1;
}

extern(C) int rxq2vq(int rxq)
{
    return rxq * 2;
}
enum int MRG_CTX_HEADER_SHIFT = 22;

extern(C) void *mergeable_len_to_ctx(uint truesize, uint headroom)
{
    return cast(void *)(cast(c_ulong)((headroom << MRG_CTX_HEADER_SHIFT) | truesize));
}

extern(C) uint mergeable_ctx_to_headroom(void *mrg_ctx)
{
    return cast(uint)(cast(c_ulong)(mrg_ctx) >> MRG_CTX_HEADER_SHIFT);
}

extern(C) uint mergeable_ctx_to_truesize(void *mrg_ctx)
{
    return cast(c_ulong)(mrg_ctx) & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}
extern(C) int vq2rxq(virtqueue *vq)
{
	return vq.index / 2;
}

extern(C) int vq2rxq(virtqueue *vq)
{
	return vq.index / 2;
}

extern(C) int vq2txq(virtqueue *vq)
{
    return (vq.index - 1) / 2;
}

extern(C) bool napi_schedule_prep(napi_struct *);
extern(C) void virtqueue_disable_cb(virtqueue *);
extern(C) void __napi_schedule(napi_struct *);

extern(C) void virtqueue_napi_schedule(napi_struct *napi, virtqueue *vq)
{
    if (napi_schedule_prep(napi)) {
        virtqueue_disable_cb(vq);
        __napi_schedule(napi);
    }
}

extern(C) uint virtqueue_enable_cb_prepare(virtqueue *);
extern(C) bool napi_complete_done(napi_struct *, int);
extern(C) bool virtqueue_poll(virtqueue *, uint);

extern(C) void virtqueue_napi_complete(napi_struct *napi, virtqueue *vq, int processed)
{
    int opaque;

    opaque = virtqueue_enable_cb_prepare(vq);
    if (napi_complete_done(napi, processed)) {
        //if (unlikely(virtqueue_poll(vq, opaque)))
        // am eliminat unlikely, pierderi de performanta!!
        if (virtqueue_poll(vq, opaque))
            virtqueue_napi_schedule(napi, vq);
    } else {
        virtqueue_disable_cb(vq);
    }
}

extern(C) pragma(inline, true) bool __dbind__virtio_has_feature(const virtio_device *vdev, uint fbit);

pragma(inline, true) bool virtio_has_feature(const virtio_device *vdev, uint fbit)
{
    return __dbind__virtio_has_feature(vdev, fbit);
}

extern(C) bool virtnet_fail_on_feature(virtio_device *vdev, uint fbit,
        const char *fname, const char *dname)
{
    if (!virtio_has_feature(vdev, fbit))
        return false;

    //dev_err(&vdev->dev, "device advertises feature %s but not %s", fname, dname);

    return true;
}


