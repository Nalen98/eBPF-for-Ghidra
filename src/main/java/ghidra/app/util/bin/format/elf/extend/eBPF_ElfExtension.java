package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class eBPF_ElfExtension extends ElfExtension {
    @Override
    public boolean canHandle(ElfHeader elf) {
        return elf.e_machine() == ElfConstants.EM_BPF && elf.is64Bit();
    }

    @Override
    public boolean canHandle(ElfLoadHelper elfLoadHelper) {
        Language language = elfLoadHelper.getProgram().getLanguage();
        return canHandle(elfLoadHelper.getElfHeader()) && "eBPF".equals(language.getProcessor().toString()) &&
            language.getLanguageDescription().getSize() == 64;
    }

    @Override
    public String getDataTypeSuffix() {
        return "eBPF";
    }

    @Override
    public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
        if (!canHandle(elfLoadHelper)) {
            return;
        }
        super.processGotPlt(elfLoadHelper, monitor);
    }
}
