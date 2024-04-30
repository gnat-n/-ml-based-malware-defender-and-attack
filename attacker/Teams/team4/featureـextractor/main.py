import pefile
import sys
import hashlib

extracted_features = {}


def extract_other_features(pe, features, header):

    if hasattr(pe, header):
        # get header
        if header == 'FILE_HEADER':
            _header = pe.FILE_HEADER
        elif header == 'OPTIONAL_HEADER':
            _header = pe.OPTIONAL_HEADER
        elif header == 'DOS_HEADER':
            _header = pe.DOS_HEADER

        for feature in features:
            try:
                value = getattr(_header, feature)
            except AttributeError:
                value = 0
            extracted_features[feature] = value
    else:
        for feature in features:
            extracted_features[feature] = 0

    # print(extracted_features)


def extract_section_features_corrected():
    features = ['PointerToLinenumbers', 'NumberOfLinenumbers', 'Characteristics', 'PointerToRawData',
                'SizeOfRawData', 'VirtualAddress', 'Misc_VirtualSize', 'NumberOfRelocations', 'PointerToRelocations']

    sections = ['text', 'data', 'pdata', 'idata',
                'rdata', 'rsrc', 'reloc', 'edata', 'tls', 'bss']

    extracted_section_names = []

    # extract existing sections and add it to the dictionary
    for section in pe.sections:
        # Get the section name
        section_name = section.Name.decode().rstrip('\0').lstrip('.')
        extracted_section_names.append(section_name)

        for feature in features:
            # Extract the attribute value
            try:
                value = getattr(section, feature, 0)
            except AttributeError:
                value = 0
            extracted_features[f"{section_name}_{feature}"] = value

    # print(extracted_section_names)
    # add rest of the sections
    for section in sections:
        if section not in extracted_section_names:
            for feature in features:
                extracted_features[f"{section}_{feature}"] = 0


def our_PEFeatureExtractor(pe):

    # extract other features
    optional_header_features = ['Magic', 'NumberOfRvaAndSizes', 'DllCharacteristics', 'MajorOperatingSystemVersion', 'AddressOfEntryPoint', 'MinorSubsystemVersion', 'CheckSum', 'Subsystem', 'MajorImageVersion', 'SizeOfInitializedData', 'BaseOfCode', 'MajorLinkerVersion', 'SizeOfUninitializedData',
                                'SizeOfImage', 'SizeOfHeapCommit', 'SizeOfStackReserve', 'MajorSubsystemVersion', 'SectionAlignment', 'FileAlignment', 'MinorLinkerVersion', 'SizeOfCode', 'LoaderFlags', 'MinorImageVersion', 'SizeOfHeapReserve', 'SizeOfHeaders', 'MinorOperatingSystemVersion', 'ImageBase']
    file_header_features = ['NumberOfSections', 'PointerToSymbolTable', 'SizeOfOptionalHeader',
                            'Machine', 'NumberOfSymbols', 'Reserved1', 'Characteristics', 'TimeDateStamp']
    dos_header_features = ['e_sp', 'e_oeminfo', 'e_lfanew', 'e_ip', 'e_magic', 'e_cs', 'e_oemid', 'e_cblp',
                           'e_maxalloc', 'e_crlc', 'e_minalloc', 'e_csum', 'e_ovno', 'e_cp', 'e_ss', 'e_lfarlc', 'e_cparhdr']

    headers = {'OPTIONAL_HEADER': optional_header_features,
               'FILE_HEADER': file_header_features, 'DOS_HEADER': dos_header_features}

    for header, features in headers.items():
        extract_other_features(pe, features, header)

    # extract section features
    extract_section_features_corrected()

    # return all features
    return extracted_features


def extract_pe_features(file_path):
    global pe
    pe = pefile.PE(file_path)
    return our_PEFeatureExtractor(pe)


if __name__ == '__main__':
    features = extract_pe_features(sys.argv[1])

    # print features
    for key, values in features.items():
        print(key, values)
