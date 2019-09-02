import dvirtio_net : gfp_t;


enum ___GFP_KSWAPD_RECLAIM = 0x400000u;
enum ___GFP_ATOMIC = 0x80000u;
enum ___GFP_HIGH = 0x20u;
enum ___GFP_DIRECT_RECLAIM = 0x200000u;
enum ___GFP_IO = 0x40u;
enum ___GFP_FS = 0x80u;

enum gfp_t __GFP_KSWAPD_RECLAIM = ___GFP_KSWAPD_RECLAIM; /* kswapd can wake */
enum gfp_t __GFP_ATOMIC = ___GFP_ATOMIC;
enum gfp_t __GFP_HIGH = ___GFP_HIGH;
enum gfp_t GFP_ATOMIC = (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM);

enum gfp_t __GFP_FS = (___GFP_FS);
enum gfp_t __GFP_IO = (___GFP_IO);
enum gfp_t __GFP_RECLAIM = (___GFP_DIRECT_RECLAIM | ___GFP_KSWAPD_RECLAIM);
enum gfp_t GFP_KERNEL = (__GFP_RECLAIM | __GFP_IO | __GFP_FS);

