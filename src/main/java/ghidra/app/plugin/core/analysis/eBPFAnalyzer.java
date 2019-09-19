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
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.app.cmd.function.AddMemoryParameterCommand;

public class eBPFAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "eBPF";

	public eBPFAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSet flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption);
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		SymbolTable table = program.getSymbolTable();
		boolean includeDynamicSymbols = true;
		SymbolIterator symbols = table.getAllSymbols(includeDynamicSymbols);
		
		for (ghidra.program.model.symbol.Symbol s : symbols) {
				
			if (s.getName().contains("syscall")){			
				Function func = program.getFunctionManager().getFunctionAt(s.getAddress());
				
				//Definitions for datatypes
				DataType dstruct = null;
				DataType dvoid = new VoidDataType();
				DataType dint = new IntegerDataType();
				DataType dchar = new CharDataType();
				DataType duint = new UnsignedIntegerDataType();	
				DataType dulong = new UnsignedLongDataType();
				DataType dushort = new UnsignedShortDataType();
				DataType dslong = new SignedQWordDataType();
				DataType duchar = new UnsignedCharDataType(); 
				DataType dvp = new PointerDataType(dvoid, 0);	
				DataType dcp = new PointerDataType(dchar, 0);	
				DataType dsp; //DataType for struct-pointer	
				
				
				//Command-vars
				SetFunctionNameCmd cmdName;
				SetReturnDataTypeCmd cmdRet;
				AddMemoryParameterCommand cmdArg1;
				AddMemoryParameterCommand cmdArg2;
				AddMemoryParameterCommand cmdArg3;
				AddMemoryParameterCommand cmdArg4;
				AddMemoryParameterCommand cmdArg5;
				
				String location =  s.getName().substring(14); //Getting address of helper
				int helper_id = Integer.parseInt(location, 16);
				switch(helper_id) {
					case(0):	
						//void bpf_unspec()
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_unspec", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dvoid , SourceType.ANALYSIS);				
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						program.flushEvents();	
						break;
					case(1):
						//void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_map_lookup_elem", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dvp , SourceType.ANALYSIS);				
						dstruct = new StructureDataType("struct bpf_map", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "map", dsp, 0, SourceType.ANALYSIS);						
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "key", dvp, 1, SourceType.ANALYSIS);				 
					 				 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						program.flushEvents();	
						break;
					case(2):
						//int bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_map_update_elem", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);				
						dstruct = new StructureDataType("struct bpf_map", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "map", dsp, 0, SourceType.ANALYSIS);						
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "key", dvp, 1, SourceType.ANALYSIS);	
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "value", dvp, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 3, SourceType.ANALYSIS);				 
					 				 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);
						program.flushEvents();	
						break;
					case(3):
						//int bpf_map_delete_elem(struct bpf_map *map, const void *key)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_map_delete_elem", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);				
						dstruct = new StructureDataType("struct bpf_map", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "map", dsp, 0, SourceType.ANALYSIS);						
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "key", dvp, 1, SourceType.ANALYSIS);				 
					 				 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						program.flushEvents();	
						break;
					case(4):
						//int bpf_probe_read(void *dst, u32 size, const void *src)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_probe_read", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "dst", dvp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "size", duint, 1, SourceType.ANALYSIS);	
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "src", dvp, 2, SourceType.ANALYSIS);				 
					 				 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						cmdArg3.applyTo(program);
						program.flushEvents();	
						break;
					case(5):
						//u64 bpf_ktime_get_ns(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_ktime_get_ns", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dulong , SourceType.ANALYSIS);		
								 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);				
						program.flushEvents();	
						break;
					case(6):
						//int bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_trace_printk", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "fmt", dcp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "fmt_size", duint, 1, SourceType.ANALYSIS);							
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);						
						program.flushEvents();							
						break;
					case(7):
						//u32 bpf_get_prandom_u32(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_prandom_u32", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), duint , SourceType.ANALYSIS);		
								 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						program.flushEvents();	
						break;
					case(8):
						//u32 bpf_get_smp_processor_id(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_smp_processor_id", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), duint , SourceType.ANALYSIS);		
								 
						cmdName.applyTo(program);
						cmdRet.applyTo(program);				
						program.flushEvents();
						break;
					case(9):
						//int bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_store_bytes", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "offset", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "from", dvp, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "len", duint, 3, SourceType.ANALYSIS);
						cmdArg5 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 4, SourceType.ANALYSIS);
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);		
						cmdArg5.applyTo(program);
						program.flushEvents();
						break;
					case(10):
						//int bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 size)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_l3_csum_replace", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "offset", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "from", dulong, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "to", dulong, 3, SourceType.ANALYSIS);
						cmdArg5 = new AddMemoryParameterCommand(func, s.getAddress(), "size", dulong, 4, SourceType.ANALYSIS);
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);		
						cmdArg5.applyTo(program);
						program.flushEvents();						
						break;
					case(11):
						//int bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_l4_csum_replace", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "offset", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "from", dulong, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "to", dulong, 3, SourceType.ANALYSIS);
						cmdArg5 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 4, SourceType.ANALYSIS);
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);		
						cmdArg5.applyTo(program);
						program.flushEvents();							
						break;
					case(12):
						//int bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_tail_call", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct bpf_map", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "ctx", dvp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "prog_array_map", dsp, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "index", duint, 2, SourceType.ANALYSIS);
											
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);						
						program.flushEvents();						
						break;
					case(13):
						//int bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_clone_redirect", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "ifindex", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 2, SourceType.ANALYSIS);
											
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);						
						program.flushEvents();						
						break;
					case(14):
						//u64 bpf_get_current_pid_tgid(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_current_pid_tgid", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dulong , SourceType.ANALYSIS);		
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);												
						program.flushEvents();						
						break;
					case(15):
						//u64 bpf_get_current_uid_gid(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_current_uid_gid", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dulong , SourceType.ANALYSIS);		
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);												
						program.flushEvents();	
						break;
					case(16):
						//int bpf_get_current_comm(char *buf, u32 size_of_buf)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_current_comm", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "buf", dcp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "size_of_buf", duint, 1, SourceType.ANALYSIS);							
											
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						program.flushEvents();	
						break;
					case(17):
						//u32 bpf_get_cgroup_classid(struct sk_buff *skb)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_cgroup_classid", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), duint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						program.flushEvents();	
						break;
					case(18):
						//int bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
						//In ghidra Api conditions we must equate__be16 with unsigned short type. 
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_vlan_push", SourceType.ANALYSIS);					
						cmdRet = new  SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "vlan_proto", dushort, 1, SourceType.ANALYSIS);	
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "vlan_tci", dushort, 2, SourceType.ANALYSIS);	
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						cmdArg3.applyTo(program);
						program.flushEvents();
						break;
					case(19):
						//int bpf_skb_vlan_pop(struct sk_buff *skb)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_vlan_pop", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						program.flushEvents();
						break;
					case(20):
						//int bpf_skb_get_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_get_tunnel_key", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						DataType dstruct2 = new StructureDataType("struct bpf_tunnel_key", 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "key", new PointerDataType(dstruct2, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "size", duint, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 3, SourceType.ANALYSIS);
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);							
						program.flushEvents();
						break;
					case(21):
						//int bpf_skb_set_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_set_tunnel_key", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						dstruct2 = new StructureDataType("struct bpf_tunnel_key", 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "key", new PointerDataType(dstruct2, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "size", duint, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 3, SourceType.ANALYSIS);
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);							
						program.flushEvents();
						break;
					case(22):
						//u64 bpf_perf_event_read(struct bpf_map *map, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_perf_event_read", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dulong , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct bpf_map", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "map", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 1, SourceType.ANALYSIS);	
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						program.flushEvents();	
						break;
					case(23):
						//int bpf_redirect(u32 ifindex, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_redirect", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "ifindex", duint, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 1, SourceType.ANALYSIS);	
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						program.flushEvents();	
						break;
					case(24):
						//u32 bpf_get_route_realm(struct sk_buff *skb)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_route_realm", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), duint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
					
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						program.flushEvents();	
						break;
					case(25):
						//int bpf_perf_event_output(struct pt_reg *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_perf_event_output", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct pt_reg", 0);
						dsp = new PointerDataType(dstruct, 0);
						dstruct2 = new StructureDataType("struct bpf_map", 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "ctx", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "map", new PointerDataType(dstruct2, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "data", dvp, 3, SourceType.ANALYSIS);
						cmdArg5 = new AddMemoryParameterCommand(func, s.getAddress(), "size", dulong, 4, SourceType.ANALYSIS);						
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);	
						cmdArg5.applyTo(program);
						program.flushEvents();
						break;
					case(26):
						//int bpf_skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_load_bytes", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						dstruct2 = new StructureDataType("struct bpf_map", 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "offset", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "to", dvp, 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "len", duint, 3, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);
						cmdArg4.applyTo(program);					
						program.flushEvents();
						break;
					case(27):
						//int bpf_get_stackid(struct pt_reg *ctx, struct bpf_map *map, u64 flags)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_stackid", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct pt_reg", 0);
						dsp = new PointerDataType(dstruct, 0);
						dstruct2 = new StructureDataType("struct bpf_map", 0);
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "ctx", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "map", new PointerDataType(dstruct2, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 2, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);									
						program.flushEvents();
						break;
					case(28):
						//s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)
						//In ghidra Api conditions we must equate __be32 and __wsum with u32 (knowing typedef).
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_csum_diff", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dslong , SourceType.ANALYSIS);		
						
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "from", new PointerDataType(duint, 0), 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "from_size", duint, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "to", new PointerDataType(duint, 0), 2, SourceType.ANALYSIS);
						cmdArg4 = new AddMemoryParameterCommand(func, s.getAddress(), "to_size", duint, 3, SourceType.ANALYSIS);
						cmdArg5 = new AddMemoryParameterCommand(func, s.getAddress(), "seed", duint, 4, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);	
						cmdArg4.applyTo(program);	
						cmdArg5.applyTo(program);	
						program.flushEvents();
						break;
					case(29):
						//int bpf_skb_get_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_get_tunnel_opt", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
												
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "opt", new PointerDataType(duchar, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "size", duint, 2, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);									
						program.flushEvents();
						break;
					case(30):
						//int bpf_skb_set_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_set_tunnel_opt", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
												
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "opt", new PointerDataType(duchar, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "size", duint, 2, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);									
						program.flushEvents();
						break;
					case(31):
						//int bpf_skb_change_proto(struct sk_buff *skb, __be16 proto, u64 flags)
						//__be16 equals u16 for big-endian
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_change_proto", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
												
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "proto", dushort, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "flags", dulong, 2, SourceType.ANALYSIS);
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);		
						cmdArg3.applyTo(program);									
						program.flushEvents();
						break;
					case(32):
						//int bpf_skb_change_type(struct sk_buff *skb, u32 type)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_change_type", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
												
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "type", duint, 1, SourceType.ANALYSIS);							
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);														
						program.flushEvents();
						break;
					case(33):
						//int bpf_skb_under_cgroup(struct sk_buff *skb, struct bpf_map *map, u32 index)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_skb_under_cgroup", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
						
						dstruct = new StructureDataType("struct sk_buff", 0);
						dsp = new PointerDataType(dstruct, 0);
						dstruct2 = new StructureDataType("struct bpf_map", 0);
												
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "map", new PointerDataType(dstruct2, 0), 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "index", duint, 2, SourceType.ANALYSIS);							
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						cmdArg3.applyTo(program);
						program.flushEvents();
						break;
					case(34):
						//u32 bpf_get_hash_recalc(struct sk_buff *skb)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_hash_recalc", SourceType.ANALYSIS);				 					 	
					  	cmdRet = new SetReturnDataTypeCmd(s.getAddress(), duint , SourceType.ANALYSIS);
					  	dstruct = new StructureDataType("struct sk_buff", 0);
					  	dsp = new PointerDataType(dstruct, 0);
					  	
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "skb", dsp, 0, SourceType.ANALYSIS);
	
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						program.flushEvents();
						break;
					case(35):
						//u64 bpf_get_current_task(void)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_get_current_task", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dulong , SourceType.ANALYSIS);		
						
						cmdName.applyTo(program);
						cmdRet.applyTo(program);						
						program.flushEvents();
						break;
					case(36):
						//int bpf_probe_write_user(void *dst, const void *src, u32 len)
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_probe_write_user", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);		
																	
						cmdArg1 = new AddMemoryParameterCommand(func, s.getAddress(), "dst", dvp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddMemoryParameterCommand(func, s.getAddress(), "src", dvp, 1, SourceType.ANALYSIS);							
						cmdArg3 = new AddMemoryParameterCommand(func, s.getAddress(), "len", duint, 2, SourceType.ANALYSIS);							
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);
						cmdArg3.applyTo(program);
						program.flushEvents();
						break;
					 default:
						 //void bpf_undef()
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_undef", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dvoid , SourceType.ANALYSIS);		
							
						cmdName.applyTo(program);
						cmdRet.applyTo(program);						
						program.flushEvents();	 
						break;
				}						
			}
		}

		return resultSet;
	}
}
