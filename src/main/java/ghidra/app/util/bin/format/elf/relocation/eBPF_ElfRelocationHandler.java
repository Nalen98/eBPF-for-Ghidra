/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.NotFoundException;

public class eBPF_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BPF;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		
		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_BPF) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();	
		int symbolIndex = relocation.getSymbolIndex();				
		long value;
		boolean appliedSymbol = true;

		if (type == 1) {			
			try {					
					int SymbolIndex= relocation.getSymbolIndex();
					ElfSymbol Symbol = elfRelocationContext.getSymbol(SymbolIndex);
					String map = Symbol.getNameAsString();				
					
					SymbolTable table = program.getSymbolTable();
					Address mapAddr = table.getSymbol(map).getAddress();
					String sec_name = elfRelocationContext.relocationTable.getSectionToBeRelocated().getNameAsString();
					if (sec_name.toString().contains("debug")) {
						return;
					}
					
					value = mapAddr.getAddressableWordOffset();		
					Byte dst = memory.getByte(relocationAddress.add(0x1));
					memory.setLong(relocationAddress.add(0x4), value);			
					memory.setByte(relocationAddress.add(0x1), (byte) (dst + 0x10));				
				}
				catch(NullPointerException e) {}
		}		

		if (appliedSymbol && symbolIndex == 0) {
			markAsWarning(program, relocationAddress, Long.toString(type),
				"applied relocation with symbol-index of 0", elfRelocationContext.getLog());
		}

	}
}
