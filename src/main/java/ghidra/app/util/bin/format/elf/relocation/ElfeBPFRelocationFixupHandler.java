package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.plugin.core.reloc.RelocationFixupHandler;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.util.CodeUnitInsertionException;

public class ElfeBPFRelocationFixupHandler extends RelocationFixupHandler {
    @Override
    public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
            Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {
                return process64BitRelocation(program, relocation, oldImageBase, newImageBase);
    }

    @Override
    public boolean handlesProgram(Program program) {
        if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
            return false;
        }
        Language language = program.getLanguage();
        if (language.getLanguageDescription().getSize() != 64) {
            return false;
        }
        Processor processor = language.getProcessor();
        return (processor.equals(Processor.findOrPossiblyCreateProcessor("eBPF")));
    }
}
