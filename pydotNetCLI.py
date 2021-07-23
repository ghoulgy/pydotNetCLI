import sys
import pefile
from collections import OrderedDict

class dotNet_Header:
    def __init__(self, full_bytes, p_cli_metadata_header, p_diff_va_rva, p_rebased_offset):
        self.pe_content = full_bytes
        self.RESOURCE_MAGIC_NUMBER = 0xBEEFCACE

        self.set_dotNet_directory(p_rebased_offset)
        self.set_meta_header(p_cli_metadata_header)
        self.print_meta_header()
        self.set_ptr_cli_end_of_metaheader(p_cli_metadata_header)
        self.set_ptr_tables_header(p_cli_metadata_header)
        self.set_stream_table_count()

        print("##### Stream Table Information #####")
        for table_name, table_size in self.dict_stream_table.items():
            print(f"[+] Stream table name: {table_name}, Stream table size: {hex(table_size)}")    
        print()

        self.set_MaskValid()

        print("##### [#~] Table Name & Table Count #####")
        for k, v in self.dict_table_get_count.items(): 
            print(f"[+] Table name: {k}, Table count: {v}")
        print()

        self.set_tide_stream_table()
        self.set_string_stream_table()
        self.set_dict_mani_rsrc_size_offset_table()
        self.set_ptr_resource_offset(p_diff_va_rva, p_rebased_offset) # Offset of first CLI resource

        print("##### Extract Resource in CLI resource #####")
        self.set_ptr_resource_data_offset(self.cli_resource_va)
        self.get_resource_data()


    def set_dotNet_directory(self, p_rebased_offset):
        self.cb = int.from_bytes(self.pe_content[p_rebased_offset : p_rebased_offset + 4], sys.byteorder)
        self.MajorRuntimeVersion = int.from_bytes(self.pe_content[p_rebased_offset + 4 : p_rebased_offset + 6], sys.byteorder)
        self.MinorRuntimeVersion = int.from_bytes(self.pe_content[p_rebased_offset+ 6 : p_rebased_offset + 8], sys.byteorder)
        self.MetaData_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 8 : p_rebased_offset + 12], sys.byteorder)
        self.MetaDataSize = int.from_bytes(self.pe_content[p_rebased_offset + 12 : p_rebased_offset + 16], sys.byteorder)
        self.Flags = int.from_bytes(self.pe_content[p_rebased_offset + 16 : p_rebased_offset + 20], sys.byteorder)
        self.EntryPointToken = int.from_bytes(self.pe_content[p_rebased_offset + 20 : p_rebased_offset + 24], sys.byteorder)
        self.Resources_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 24 : p_rebased_offset + 28], sys.byteorder)
        self.ResourcesSize = int.from_bytes(self.pe_content[p_rebased_offset + 28 : p_rebased_offset + 32], sys.byteorder)
        self.StrongNameSignature_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 32 : p_rebased_offset + 36], sys.byteorder)
        self.StringNameSignature_Size = int.from_bytes(self.pe_content[p_rebased_offset + 36 : p_rebased_offset + 40], sys.byteorder)
        self.CodeManagerTable_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 40 : p_rebased_offset + 44], sys.byteorder)
        self.CodeManagerTable_Size = int.from_bytes(self.pe_content[p_rebased_offset + 44 : p_rebased_offset + 48], sys.byteorder)
        self.VTableFixups_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 48 : p_rebased_offset + 52], sys.byteorder)
        self.VTableFixups_Size = int.from_bytes(self.pe_content[p_rebased_offset + 52 : p_rebased_offset + 56], sys.byteorder)
        self.ExportAddressTableJumps_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 56 : p_rebased_offset + 60], sys.byteorder)
        self.ExportAddressTableJumps_Size = int.from_bytes(self.pe_content[p_rebased_offset + 60 : p_rebased_offset + 64], sys.byteorder)
        self.ManagedNativeHeader_RVA = int.from_bytes(self.pe_content[p_rebased_offset + 68 : p_rebased_offset + 72], sys.byteorder)
        self.ManagedNativeHeader_Size = int.from_bytes(self.pe_content[p_rebased_offset + 72 : p_rebased_offset + 76], sys.byteorder)


    def set_meta_header(self, p_ptr_cli_metadata_header):
        self.cli_meta_header_Signature = int.from_bytes(self.pe_content[p_ptr_cli_metadata_header : p_ptr_cli_metadata_header + 4], sys.byteorder)
        self.cli_meta_header_MajorVersion = int.from_bytes(self.pe_content[p_ptr_cli_metadata_header + 4 : p_ptr_cli_metadata_header + 6], sys.byteorder)
        self.cli_meta_header_MinorVersion = int.from_bytes(self.pe_content[p_ptr_cli_metadata_header + 6 : p_ptr_cli_metadata_header + 8], sys.byteorder)
        self.cli_meta_header_VersionLength = int.from_bytes(self.pe_content[p_ptr_cli_metadata_header + 12 : p_ptr_cli_metadata_header + 16], sys.byteorder)
        self.cli_meta_header_VersionName = self.pe_content[p_ptr_cli_metadata_header + 14 : p_ptr_cli_metadata_header + self.cli_meta_header_VersionLength + 16].decode()
        ptr_after_VersionName = p_ptr_cli_metadata_header + self.cli_meta_header_VersionLength
        self.cli_meta_header_Flags = int.from_bytes(self.pe_content[ptr_after_VersionName + 16 : ptr_after_VersionName + 18], sys.byteorder)
        self.cli_meta_header_NumberOfStreams = int.from_bytes(self.pe_content[ptr_after_VersionName + 18 : ptr_after_VersionName + 20], sys.byteorder)
        self.cli_meta_header_Size = int.from_bytes(self.pe_content[ptr_after_VersionName + 20 : ptr_after_VersionName + 22], sys.byteorder)


    def print_meta_header(self):
        print("##### MetaData Header Information #####")
        print(f"[+] Signature: {hex(self.cli_meta_header_Signature)}")
        print(f"[+] Major Version: {self.cli_meta_header_MajorVersion}")
        print(f"[+] Minor Version: {self.cli_meta_header_MinorVersion}")
        print(f"[+] Version Length: {self.cli_meta_header_VersionLength}")
        print(f"[+] Version Name: {self.cli_meta_header_VersionName}")
        print(f"[+] Flags: {hex(self.cli_meta_header_Flags)}")
        print(f"[+] Number of Streams: {self.cli_meta_header_NumberOfStreams}")
        print(f"[+] Header Size: {hex(self.cli_meta_header_Size)}\n")


    def set_ptr_cli_end_of_metaheader(self, p_ptr_cli_metadata_header):
        self.ptr_cli_end_of_metaheader = p_ptr_cli_metadata_header + self.cli_meta_header_VersionLength + 16 + 4


    def set_ptr_tables_header(self, p_ptr_cli_metadata_header):
        self.ptr_cli_tables_header = p_ptr_cli_metadata_header + self.cli_meta_header_Size


    def set_stream_table_count(self):
        self.dict_stream_table = {}
        tmp_ptr_stream_table = 0

        while(tmp_ptr_stream_table <= (self.cli_meta_header_Size - (24 + self.cli_meta_header_VersionLength))):
            if self.pe_content[self.ptr_cli_end_of_metaheader + tmp_ptr_stream_table] == 35: # Looking for '#'
                init_ptr = tmp_ptr_stream_table
                while(self.pe_content[self.ptr_cli_end_of_metaheader + tmp_ptr_stream_table + 3] != 0):
                    tmp_ptr_stream_table += 4
                stream_table_name = self.pe_content[self.ptr_cli_end_of_metaheader + init_ptr: self.ptr_cli_end_of_metaheader + tmp_ptr_stream_table + 4].decode().rstrip('\x00')
                if stream_table_name in self.dict_stream_table.keys():
                    stream_table_name += "_2"
                self.dict_stream_table[stream_table_name] = int.from_bytes(self.pe_content[self.ptr_cli_end_of_metaheader + init_ptr - 4: self.ptr_cli_end_of_metaheader + init_ptr], sys.byteorder)

            tmp_ptr_stream_table += 4


    def set_MaskValid(self):
        self.cli_MaskValid = int.from_bytes(self.pe_content[self.ptr_cli_tables_header + 8 : self.ptr_cli_tables_header + 16], sys.byteorder)
        dict_mask_table = {
            "Module": 0x1,
            "TypeRef": 0x2,
            "TypeDef": 0x4,
            "FieldPtr": 0x8,
            "Field": 0x10,
            "MethodPtr": 0x20,
            "Method": 0x40,
            "ParamPtr": 0x80,
            "Param": 0x100,
            "InterfaceImpl": 0x200,
            "MemberRef": 0x400,
            "Constant": 0x800,
            "CustomAttribute": 0x1000,
            "FieldMarshal": 0x2000,
            "DeclSecurity": 0x4000,
            "ClassLayout": 0x8000,
            "FieldLayout": 0x10000,
            "StandAloneSig": 0x20000,
            "EventMap": 0x40000,
            "EventPtr": 0x80000,
            "Event": 0x100000,
            "PropertyMap": 0x200000,
            "PropertyPtr": 0x400000,
            "Property": 0x800000,
            "MethodSemantics": 0x1000000,
            "MethodImpl": 0x2000000,
            "ModuleRef": 0x4000000,
            "TypeSpec": 0x8000000,
            "ImplMap": 0x10000000,
            "FieldRVA": 0x20000000,
            "ENCLog": 0x40000000,
            "ENCMap": 0x80000000,
            "Assembly": 0x100000000,
            "AssemblyProcessor": 0x200000000,
            "AssemblyOS": 0x400000000,
            "AssemblyRef": 0x800000000,
            "AssemblyRefProcessor": 0x1000000000,
            "AssemblyRefOS": 0x2000000000,
            "File": 0x4000000000,
            "ExportedType": 0x8000000000,
            "ManifestResource": 0x10000000000,
            "NestedClass": 0x20000000000,
            "GenericParam": 0x40000000000,
            "MethodSpec": 0x80000000000,
            "GenericParamConstraint": 0x100000000000,
            "Reserved 2D": 0x200000000000,
            "Reserved 2E": 0x400000000000,
            "Reserved 2F": 0x800000000000,
            "Document": 0x1000000000000,
            "MethodDebugInformation": 0x2000000000000,
            "LocalScope": 0x4000000000000,
            "LocalVariable": 0x8000000000000,
            "LocalConstant": 0x10000000000000,
            "ImportScope": 0x20000000000000,
            "StateMachineMethod": 0x40000000000000,
            "CustomeDebugInformation": 0x80000000000000,
            "Reserved 38": 0x100000000000000,
            "Reserved 39": 0x200000000000000,
            "Reserved 3A": 0x400000000000000,
            "Reserved 3B": 0x800000000000000,
            "Reserved 3C": 0x1000000000000000,
            "Reserved 3D": 0x2000000000000000,
            "Reserved 3E": 0x4000000000000000,
            "Reserved 3F": 0x8000000000000000,
        }

        self.ptr_cli_end_tables_header = self.ptr_cli_tables_header + 16 + 8
        self.dict_table_get_count = {}

        for table_name, table_count in dict_mask_table.items():
            if self.cli_MaskValid & table_count == table_count:
                self.dict_table_get_count[table_name] = int.from_bytes(pe_content[self.ptr_cli_end_tables_header : self.ptr_cli_end_tables_header + 4], sys.byteorder)
                self.ptr_cli_end_tables_header += 4


    def set_tide_stream_table(self):
        # table_enum
        dict_dword_table_size = {
            "Module": 10,
            "TypeRef": 6,
            "TypeDef": 14,
        #    "FieldPtr": ?,
            "Field": 6,
        #    "MethodPtr": ?,
            "Method": 14,
        #    "ParamPtr": ?,
            "Param": 6,
            "InterfaceImpl": 4,
            "MemberRef": 6,
            "Constant": 6,
            "CustomAttribute": 6,
            "FieldMarshal": 4,
            "DeclSecurity": 6,
            "ClassLayout": 8,
        #    "FieldLayout": ?,
            "StandAloneSig": 2,
            "EventMap": 4,
        #    "EventPtr": ?,
            "Event": 6,
            "PropertyMap": 4,
        #    "PropertyPtr": ?,
            "Property": 6,
            "MethodSemantics": 6,
            "MethodImpl": 6,
            "ModuleRef": 2,
            "TypeSpec": 2,
            "ImplMap": 8,
            "FieldRVA": 6,
            "ENCLog": 8,
            "ENCMap": 4,
            "Assembly": 22,
        #    "AssemblyProcessor": ?,
        #    "AssemblyOS": ?,
            "AssemblyRef": 20,
        #    "AssemblyRefProcessor": ?,
        #    "AssemblyRefOS": ?,
        #    "File": ?,
        #    "ExportedType": ?,
            "ManifestResource": 12,
            "NestedClass": 4,
            "GenericParam": 8,
            "MethodSpec": 4,
            "GenericParamConstraint": 4,
        #    "Reserved 2D": ?,
        #    "Reserved 2E": ?,
        #    "Reserved 2F": ?,
        #    "Document": ?,
        #    "MethodDebugInformation": ?,
        #    "LocalScope": ?,
        #    "LocalVariable": ?,
        #    "LocalConstant": ?,
        #    "ImportScope": ?,
        #    "StateMachineMethod": ?,
        #    "CustomeDebugInformation": ?,
        #    "Reserved 38": ?,
        #    "Reserved 39": ?,
        #    "Reserved 3A": ?,
        #    "Reserved 3B": ?,
        #    "Reserved 3C": ?,
        #    "Reserved 3D": ?,
        #    "Reserved 3E": ?,
        #    "Reserved 3F": ?,
        }

        self.arr_mani_rsrc_name_offset = []
        self.arr_mani_rsrc_offset = []

        for mani_table_name, mani_table_count in self.dict_table_get_count.items():
            if mani_table_count == 0:
                continue
            if mani_table_name == "ManifestResource":
                """
                Offset dword
                Flag dword
                Name word
                Implementation word
                """
                tmp = self.ptr_cli_end_tables_header

                for i in range(mani_table_count):
                    mani_rsrc_offset = int.from_bytes(self.pe_content[tmp : tmp + 4], sys.byteorder)
                    mani_rsrc_name_offset = self.pe_content[tmp + 8:tmp + 10]                    
                    tmp += 12
                    self.arr_mani_rsrc_name_offset.append(mani_rsrc_name_offset)
                    self.arr_mani_rsrc_offset.append(mani_rsrc_offset)
            try:
                self.ptr_cli_end_tables_header += dict_dword_table_size[mani_table_name] * mani_table_count
            except:
                print(f"[-] Please fill up the mani_table_name ({mani_table_name}), count ({mani_table_count}) in dict_dword_table_size (Line 186). Use CFF Explorer to check to actual section size")
                self.exit_wrapper()

        self.ptr_to_string_stream_table = self.ptr_cli_tables_header + self.dict_stream_table["#~"] # Move to strings stream table


    def set_string_stream_table(self):
        self.string_stream_table = self.pe_content[self.ptr_to_string_stream_table : self.ptr_to_string_stream_table + self.dict_stream_table["#Strings"]]


    def set_dict_mani_rsrc_size_offset_table(self):
        self.dict_mani_rsrc_size_offset_table = OrderedDict()
        name_idx = 1
        if len(self.arr_mani_rsrc_name_offset) == len(self.arr_mani_rsrc_offset):
            for name_offset, rsrc_size in zip(self.arr_mani_rsrc_name_offset, self.arr_mani_rsrc_offset):
                name_offset = int.from_bytes(name_offset, sys.byteorder)
                ptr_end_of_rsrc_name = self.string_stream_table.find(b"\x00", name_offset)
                string_stream_name = self.string_stream_table[name_offset : ptr_end_of_rsrc_name].decode()
                if string_stream_name in self.dict_mani_rsrc_size_offset_table.keys():
                    string_stream_name += f"_{name_idx}"
                    name_idx += 1

                self.dict_mani_rsrc_size_offset_table[string_stream_name] = rsrc_size
        print(f"[+] Total resource files: {len(self.dict_mani_rsrc_size_offset_table)}")


    def set_ptr_resource_offset(self, p_diff_va_rva, p_rebased_offset):
        self.cli_resource_rva = int.from_bytes(self.pe_content[p_rebased_offset + 24 : p_rebased_offset + 28], sys.byteorder)
        self.cli_resource_va = self.cli_resource_rva - p_diff_va_rva + 4


    def set_ptr_resource_data_offset(self, p_rsrc_offset):
        self.rsrc_content_size = int.from_bytes(self.pe_content[p_rsrc_offset - 4 : p_rsrc_offset], sys.byteorder)
        self.cli_NumberOfResources = 0
        self.cli_NumberOfTypes = 0

        if int.from_bytes(self.pe_content[p_rsrc_offset : p_rsrc_offset + 4], sys.byteorder) == self.RESOURCE_MAGIC_NUMBER:
            '''
            Magic dword
            NumberOfReaderTypes dword
            SizeOfReaderTypes dword
            '''
            cli_SizeOfReaderTypes = int.from_bytes(self.pe_content[p_rsrc_offset + 8 : p_rsrc_offset + 12], sys.byteorder)
            ptr_cli_skipped_reader = p_rsrc_offset + 12 + cli_SizeOfReaderTypes
            ptr_cur = ptr_cli_skipped_reader + 12 # e.g. 0xE130
            '''
            Version dword
            NumberOfResources dword
            NumberOfTypes dword
            '''
            self.cli_NumberOfResources = int.from_bytes(self.pe_content[ptr_cli_skipped_reader + 4 : ptr_cli_skipped_reader + 8], sys.byteorder)
            self.cli_NumberOfTypes = int.from_bytes(self.pe_content[ptr_cli_skipped_reader + 8 : ptr_cli_skipped_reader + 12], sys.byteorder)

            for i in range(self.cli_NumberOfTypes):
                if self.pe_content[ptr_cur] <= 255:
                    val_size = 1

                else:
                    val_size = 0

                ptr_cur += self.pe_content[ptr_cur]
                ptr_cur += val_size

            pos = ptr_cur - p_rsrc_offset

            align = pos & 7

            if align != 0:
              ptr_cur += (8 - align)

            ptr_cur += (4 * self.cli_NumberOfResources)

            ptr_cur += (4 * self.cli_NumberOfResources)

            cli_dataSectionOffset = int.from_bytes(self.pe_content[ptr_cur : ptr_cur + 4], sys.byteorder)

            ptr_cli_DataSection = cli_dataSectionOffset + p_rsrc_offset
            self.cli_pName = ptr_cur + 4

            return ptr_cli_DataSection

        elif int.from_bytes(self.pe_content[p_rsrc_offset : p_rsrc_offset + 2], sys.byteorder) == 0x5a4d:
            return p_rsrc_offset

        else:
            print(f"[+] Random resources file")
            return p_rsrc_offset


    def get_resource_data(self):
        if self.cli_resource_va == 0 or self.ResourcesSize == 0:
            print("[-] Probably packed or no rsrc found!")
            self.exit_wrapper()

        sum_of_size = 0
        arr_mani_rsrc_size = []
        tmp_rsrc_offset = 0
        for rsrc_name, rsrc_offset in self.dict_mani_rsrc_size_offset_table.items():
            if rsrc_offset == 0:
                tmp_rsrc_offset = rsrc_offset
                tmp_ptr_cli_DataSection = self.cli_resource_va

            else:
                arr_mani_rsrc_size.append(rsrc_offset - tmp_rsrc_offset)
                sum_of_size += (rsrc_offset - tmp_rsrc_offset)
                tmp_rsrc_offset = rsrc_offset

        arr_mani_rsrc_size.append((self.cli_resource_va - 4 + self.ResourcesSize) - (sum_of_size + self.cli_resource_va)) # Last mani rsrc size

        rsrc_idx = 0
        for rsrc_name, rsrc_offset in self.dict_mani_rsrc_size_offset_table.items():
            self.dict_mani_rsrc_size_offset_table[rsrc_name] = (rsrc_offset + self.cli_resource_va, arr_mani_rsrc_size[rsrc_idx])
            rsrc_idx += 1

        accumulate_rsrc_size = 0
        for rsrc_name, list_rsrc_info in self.dict_mani_rsrc_size_offset_table.items():
            if accumulate_rsrc_size >= self.ResourcesSize - 4:
                break

            v_ptr_cli_DataSection = self.set_ptr_resource_data_offset(list_rsrc_info[0])
            accumulate_rsrc_size += list_rsrc_info[1]

            # Check resource type == BYTE ARRAY
            if self.pe_content[v_ptr_cli_DataSection] == 0x20:
                self.rsrc_content_size = int.from_bytes(self.pe_content[v_ptr_cli_DataSection + 1 : v_ptr_cli_DataSection + 5], sys.byteorder)
                array_ptr_cur = v_ptr_cli_DataSection + 5

                if int.from_bytes(self.pe_content[array_ptr_cur : array_ptr_cur + 2], sys.byteorder) == 0x8b1f: # Gzip header
                    print("[!] GZip file detected")
                    rsrc_content = self.pe_content[array_ptr_cur : array_ptr_cur + self.rsrc_content_size]
                
                else:
                    print("[!] Random file detected. Kindly check it")
                    rsrc_content = self.pe_content[array_ptr_cur : array_ptr_cur + self.rsrc_content_size]
            
            elif int.from_bytes(self.pe_content[v_ptr_cli_DataSection : v_ptr_cli_DataSection + 2], sys.byteorder) == 0x5a4d:
                print("[!] MZ file detected")
                rsrc_content = self.pe_content[v_ptr_cli_DataSection : v_ptr_cli_DataSection + self.rsrc_content_size]

            else:
                rsrc_content = self.pe_content[list_rsrc_info[0] : list_rsrc_info[0] + self.rsrc_content_size] # Starts from RESORUCE_MAGIC_HEADER to end of resource byte

            print(f"[+] Resources Name: {rsrc_name}")
            print(f"[+] Pointer to resource data section: {hex(v_ptr_cli_DataSection)}")
            print(f"[+] Resource offset: {hex(list_rsrc_info[0])}")
            print(f"[+] Resource section size: {hex(list_rsrc_info[1])}")
            print(f"[+] Resource content size: {hex(self.rsrc_content_size)}")
            print(f"[+] Number of sub resources: {self.cli_NumberOfResources}")
            print(f"[+] Number of resources type: {self.cli_NumberOfTypes}")
            print(f"[+] {accumulate_rsrc_size} of total {self.ResourcesSize - 4} resource size")

            try:
                with open(f"{rsrc_name}.bin", 'wb') as fwrite:
                    fwrite.write(rsrc_content)
                fwrite.close()

                print(f"[+] {rsrc_name}.bin extract successful !")
            except:
                print(f"[-] {rsrc_name}.bin extract failed ...")

            input("##### Next Resource File #####")

    def exit_wrapper(self):
        print("[-] Exit...")
        exit(0)


### START ###
if len(sys.argv) != 2:
    print("[+] Usage: pydotNetCLI.py <filename>")
else: 
    exe_path = sys.argv[1]

    with open(exe_path, 'rb') as f:
        pe_content = f.read()
    f.close()

    try:
        pe = pefile.PE(exe_path)

    except OSError as e:
        print(e)

    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)

    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    com_va = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
    if com_va:
        for section in pe.sections:
            if  ".text" in section.Name.decode("utf-8"):
                rva = pe.OPTIONAL_HEADER.BaseOfCode # Usually 0x2000
                diff_va_rva = section.VirtualAddress - section.PointerToRawData

                if section.VirtualAddress <= com_va and (section.VirtualAddress + section.SizeOfRawData > com_va):
                    new_offset = section.PointerToRawData + (com_va - section.VirtualAddress) # 0x208

        cli_metadata_rva = int.from_bytes(pe_content[new_offset + 8 : new_offset + 12], sys.byteorder)
        cli_metadata_header = cli_metadata_rva - diff_va_rva

        # dotNet CLI Header Parsing
        dotnet = dotNet_Header(pe_content, cli_metadata_header, diff_va_rva, new_offset)
    else:
        print("[-] Not a dotNet PE file !")