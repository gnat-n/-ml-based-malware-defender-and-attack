import os
import lief

def extract_features(file_path):
    pe = lief.parse(file_path)
    features = dict()

    # Extracting DOS Header features
    dos_header = pe.dos_header
    features["dos_header"] = { 
        "e_magic": dos_header.magic,
        "e_cblp": dos_header.used_bytes_in_the_last_page,
        "e_cp": dos_header.pages_in_file,
        "e_crlc": dos_header.relocations,
        "e_cparhdr": dos_header.size_of_header_in_paragraphs,
        "e_minalloc": dos_header.minimum_extra_paragraphs,
        "e_maxalloc": dos_header.maximum_extra_paragraphs,
        "e_ss": dos_header.initial_relative_ss,
        "e_sp": dos_header.initial_sp,
        "e_csum": dos_header.checksum,
        "e_ip": dos_header.initial_ip,
        "e_cs": dos_header.initial_relative_cs,
        "e_lfarlc": dos_header.addressof_relocation_table,
        "e_ovno": dos_header.overlay_number,
        "e_oemid": dos_header.oem_id,
        "e_oeminfo": dos_header.oem_info,
        "e_lfanew": dos_header.addressof_new_exeheader
    }

    # Extracting Header features
    header = pe.header
    features["header"] = {
        "Machine": header.machine,
        "NumberOfSections": header.numberof_sections,
        "TimeDateStamp": header.time_date_stamps,
        "PointerToSymbolTable": header.pointerto_symbol_table,
        "NumberOfSymbols": header.numberof_symbols,
        "SizeOfOptionalHeader": header.sizeof_optional_header,
        "Characteristics": header.characteristics_lists
    }

    # Extracting Optional Header features
    optional_header = pe.optional_header
    features["optional_header"] = {
        "Magic": optional_header.magic,
        "MajorLinkerVersion": optional_header.major_linker_version,
        "MinorLinkerVersion": optional_header.minor_linker_version,
        "SizeOfCode": optional_header.sizeof_code,
        "SizeOfInitializedData": optional_header.sizeof_initialized_data,
        "SizeOfUninitializedData": optional_header.sizeof_uninitialized_data,
        "AddressOfEntryPoint": optional_header.addressof_entrypoint,
        "BaseOfCode": optional_header.baseof_code,
        "ImageBase": optional_header.imagebase,
        "SectionAlignment": optional_header.section_alignment,
        "FileAlignment": optional_header.file_alignment,
        "MajorOperatingSystemVersion": optional_header.major_operating_system_version,
        "MinorOperatingSystemVersion": optional_header.minor_operating_system_version,
        "MajorImageVersion": optional_header.major_image_version,
        "MinorImageVersion": optional_header.minor_image_version,
        "MajorSubsystemVersion": optional_header.major_subsystem_version,
        "MinorSubsystemVersion": optional_header.minor_subsystem_version,
        "Win32VersionValue": optional_header.win32_version_value,
        "SizeOfImage": optional_header.sizeof_image,
        "SizeOfHeaders": optional_header.sizeof_headers,
        "CheckSum": optional_header.checksum,
        "Subsystem": optional_header.subsystem,
        "DllCharacteristics": optional_header.dll_characteristics_lists,
        "SizeOfStackReserve": optional_header.sizeof_stack_reserve,
        "SizeOfStackCommit": optional_header.sizeof_stack_commit,
        "SizeOfHeapReserve": optional_header.sizeof_heap_reserve,
        "SizeOfHeapCommit": optional_header.sizeof_heap_commit,
        "LoaderFlags": optional_header.loader_flags,
        "NumberOfRvaAndSizes": optional_header.numberof_rva_and_size
    }

    # Extracting Section features
    features["sections"] = [sec.name for sec in pe.sections]

    # Extracting Import features
    features["imports"] = [imp.name for imp in pe.imports]

    # Extracting Export features
    features["exports"] = [exp.name for exp in pe.exported_functions] if pe.has_exports else []

    # Extracting Resources
    features["resources"] = [res.id for res in pe.resources] if pe.has_resources else []

    return features

def process_directory(directory_path):
    features_list = []
    for file_name in os.listdir(directory_path):
        # if file_name.endswith(".pe"):
            file_path = os.path.join(directory_path, file_name)
            features = extract_features(file_path)
            features_list.append(features)
    # return features_list

# Use the function
features = process_directory("D:\Yash-docs\Assignments-TAMU\ML\ML_model\ML-for-Cyber-Competition\defense\datasets\mw2")