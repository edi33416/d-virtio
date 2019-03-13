import list_head_h;
import mod_devicetable_h;
import spinlock_types_h : spinlock_t;
import device_h : device;

struct cpumask;
struct vq_callback_t;
struct vringh_config_ops;
struct irq_affinity;

struct virtio_config_ops {
    void function(virtio_device *vdev, uint offset,
            void *buf, uint len) get;
    void function(virtio_device *vdev, uint offset,
            const void *buf, uint len) set;
    uint function(virtio_device *vdev) generation;
    ubyte function(virtio_device *vdev) get_status;
    void function(virtio_device *vdev, ubyte status) set_status;
    void function(virtio_device *vdev) reset;
    int function(virtio_device *, uint nvqs,
            virtqueue*[] vqs, vq_callback_t*[] callbacks,
            const(char *)[] names, const bool *ctx,
            irq_affinity *desc) find_vqs;
    void function(virtio_device *) del_vqs;
    ulong function(virtio_device *vdev) get_features;
    int function(virtio_device *vdev) finalize_features;
    const char * function(virtio_device *vdev) bus_name;
    int function(virtqueue *vq, const cpumask *cpu_mask) set_vq_affinity;
    const cpumask * function(virtio_device *vdev, int index) get_vq_affinity;
}

struct virtio_device {
    int index;
    bool failed;
    bool config_enabled;
    bool config_change_pending;
    spinlock_t config_lock;
    device dev;
    virtio_device_id id;
    const virtio_config_ops *config;
    const vringh_config_ops *vringh_config;
    list_head vqs;
    ulong features;
    void *priv;
}

struct virtqueue {
    list_head list;
    void function(virtqueue *vq) callback;
    const char *name;
    virtio_device *vdev;
    uint index;
    uint num_free;
    void *priv;
}

