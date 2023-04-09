package ghidra.app.util.bin.format.elf.relocation;

public class eBPF_ElfRelocationConstants {

    /** No operation needed */
    public static final int R_BPF_NONE = 0;
    /** S + A */
    public static final int R_BPF_64_64 = 1;
    /** S + A */
    public static final int R_BPF_64_ABS64 = 2;
    /** S + A */
    public static final int R_BPF_64_ABS32 = 3;
    /** S + A */
    public static final int R_BPF_64_NODYLD32 = 4;
    /** (S + A) / 8 - 1 */
    public static final int R_BPF_64_32 = 10;

    private eBPF_ElfRelocationConstants() {
        // no construct
    }
}
