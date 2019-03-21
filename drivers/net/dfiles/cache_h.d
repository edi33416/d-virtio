
enum CONFIG_X86_L1_CACHE_SHIFT = 6;

enum L1_CACHE_SHIFT = CONFIG_X86_L1_CACHE_SHIFT;

enum L1_CACHE_BYTES = (1 << L1_CACHE_SHIFT);

enum SMP_CACHE_BYTES = L1_CACHE_BYTES;

version (CONFIG_SMP)
{
    enum ____cacheline_aligned = "align(SMP_CACHE_BYTES) ";
    enum ____cacheline_aligned_in_smp = ____cacheline_aligned;
}
else
{
    enum ____cacheline_aligned = "";  //ca sa nu dea eroare cand o import
    enum ____cacheline_aligned_in_smp = "";
}




