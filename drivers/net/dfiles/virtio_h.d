import list_head_h;
import mod_devicetable_h;
import spinlock_types_h;

struct virtio_config_ops;
struct vringh_config_ops;
struct virtio_device;
/*struct virtio_device {*/
    //int index;
    //bool failed;
    //bool config_enabled;
    //bool config_change_pending;
    //spinlock_t config_lock;
    //device dev;
    //virtio_device_id id;
    //const virtio_config_ops *config;
    //const vringh_config_ops *vringh_config;
    //list_head vqs;
    //ulong features;
    //void *priv;
//}

struct virtqueue {
	list_head list;
	void function(virtqueue *vq) callback;
	const char *name;
	virtio_device *vdev;
	uint index;
	uint num_free;
	void *priv;
}

