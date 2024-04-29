import pandas as pd
import pefile

from .attribute_extractor import PEAttributeExtractor

def extract_header_features(pe: pefile.PE):
    features = []
    
    ### DOS header
    features.append(pe.DOS_HEADER.e_magic)
    features.append(pe.DOS_HEADER.e_cblp)
    features.append(pe.DOS_HEADER.e_cp)
    features.append(pe.DOS_HEADER.e_crlc)
    features.append(pe.DOS_HEADER.e_cparhdr)
    features.append(pe.DOS_HEADER.e_minalloc)
    features.append(pe.DOS_HEADER.e_maxalloc)
    features.append(pe.DOS_HEADER.e_ss)
    features.append(pe.DOS_HEADER.e_sp)
    features.append(pe.DOS_HEADER.e_csum)
    features.append(pe.DOS_HEADER.e_ip)
    features.append(pe.DOS_HEADER.e_cs)
    features.append(pe.DOS_HEADER.e_lfarlc)
    features.append(pe.DOS_HEADER.e_ovno)
    features.append(pe.DOS_HEADER.e_oemid)
    features.append(pe.DOS_HEADER.e_oeminfo)
    features.append(pe.DOS_HEADER.e_lfanew)

    ## File Header
    features.append(pe.FILE_HEADER.Machine)
    features.append(pe.FILE_HEADER.NumberOfSections)
    features.append(pe.FILE_HEADER.TimeDateStamp)
    features.append(pe.FILE_HEADER.PointerToSymbolTable)
    features.append(pe.FILE_HEADER.NumberOfSymbols)
    features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    features.append(pe.FILE_HEADER.Characteristics)

    ## Optional Header
    features.append(pe.OPTIONAL_HEADER.Magic)
    features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.SizeOfCode)
    features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    features.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    features.append(pe.OPTIONAL_HEADER.BaseOfCode)
    features.append(pe.OPTIONAL_HEADER.ImageBase)
    features.append(pe.OPTIONAL_HEADER.SectionAlignment)
    features.append(pe.OPTIONAL_HEADER.FileAlignment)
    features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    features.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    features.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    features.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    features.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    features.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    features.append(pe.OPTIONAL_HEADER.Reserved1)
    features.append(pe.OPTIONAL_HEADER.SizeOfImage)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    features.append(pe.OPTIONAL_HEADER.CheckSum)
    features.append(pe.OPTIONAL_HEADER.Subsystem)
    features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    features.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    features.append(pe.OPTIONAL_HEADER.LoaderFlags)
    features.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    
    return features

def exract_section_features(pe: pefile.PE):
    features = [0] * 92
    
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        for section in pe.sections:
            if(section.Name.decode('unicode_escape').rstrip('\x00') == '.text'):
                features[2] = section.Misc_VirtualSize
                features[3] = section.VirtualAddress
                features[4] = section.SizeOfRawData
                features[5] = section.PointerToRawData
                features[6] = section.PointerToRelocations
                features[7] = section.PointerToLinenumbers
                features[8] = section.NumberOfRelocations
                features[9] = section.NumberOfLinenumbers
                features[10] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.data'):
                features[11] = section.Misc_VirtualSize
                features[12] = section.VirtualAddress
                features[13] = section.SizeOfRawData
                features[14] = section.PointerToRawData
                features[15] = section.PointerToRelocations
                features[16] = section.PointerToLinenumbers
                features[17] = section.NumberOfRelocations
                features[18] = section.NumberOfLinenumbers
                features[19] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.rdata'):
                features[20] = section.Misc_VirtualSize
                features[21] = section.VirtualAddress
                features[22] = section.SizeOfRawData
                features[23] = section.PointerToRawData
                features[24] = section.PointerToRelocations
                features[25] = section.PointerToLinenumbers
                features[26] = section.NumberOfRelocations
                features[27] = section.NumberOfLinenumbers
                features[28] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.bss'):
                features[29] = section.Misc_VirtualSize
                features[30] = section.VirtualAddress
                features[31] = section.SizeOfRawData
                features[32] = section.PointerToRawData
                features[33] = section.PointerToRelocations
                features[34] = section.PointerToLinenumbers
                features[35] = section.NumberOfRelocations
                features[36] = section.NumberOfLinenumbers
                features[37] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.idata'):
                features[38] = section.Misc_VirtualSize
                features[39] = section.VirtualAddress
                features[40] = section.SizeOfRawData
                features[41] = section.PointerToRawData
                features[42] = section.PointerToRelocations
                features[43] = section.PointerToLinenumbers
                features[44] = section.NumberOfRelocations
                features[45] = section.NumberOfLinenumbers
                features[46] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.edata'):
                features[47] = section.Misc_VirtualSize
                features[48] = section.VirtualAddress
                features[49] = section.SizeOfRawData
                features[50] = section.PointerToRawData
                features[51] = section.PointerToRelocations
                features[52] = section.PointerToLinenumbers
                features[53] = section.NumberOfRelocations
                features[54] = section.NumberOfLinenumbers
                features[55] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.rsrc'):
                features[56] = section.Misc_VirtualSize
                features[57] = section.VirtualAddress
                features[58] = section.SizeOfRawData
                features[59] = section.PointerToRawData
                features[60] = section.PointerToRelocations
                features[61] = section.PointerToLinenumbers
                features[62] = section.NumberOfRelocations
                features[63] = section.NumberOfLinenumbers
                features[64] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.reloc'):
                features[65] = section.Misc_VirtualSize
                features[66] = section.VirtualAddress
                features[67] = section.SizeOfRawData
                features[68] = section.PointerToRawData
                features[69] = section.PointerToRelocations
                features[70] = section.PointerToLinenumbers
                features[71] = section.NumberOfRelocations
                features[72] = section.NumberOfLinenumbers
                features[73] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.tls'):
                features[74] = section.Misc_VirtualSize
                features[75] = section.VirtualAddress
                features[76] = section.SizeOfRawData
                features[77] = section.PointerToRawData
                features[78] = section.PointerToRelocations
                features[79] = section.PointerToLinenumbers
                features[80] = section.NumberOfRelocations
                features[81] = section.NumberOfLinenumbers
                features[82] = section.Characteristics
            if (section.Name.decode('unicode_escape').rstrip('\x00') == '.pdata'):
                features[83] = section.Misc_VirtualSize
                features[84] = section.VirtualAddress
                features[85] = section.SizeOfRawData
                features[86] = section.PointerToRawData
                features[87] = section.PointerToRelocations
                features[88] = section.PointerToLinenumbers
                features[89] = section.NumberOfRelocations
                features[90] = section.NumberOfLinenumbers
                features[91] = section.Characteristics
    
    return features[2:]

def extract_features_1(file_path: str):
    features = []
    try:
        pe = pefile.PE(file_path)
        
        pe_header_features = extract_header_features(pe)
        pe_section_features = exract_section_features(pe)
        
        features = pe_header_features + pe_section_features
        print(len(features))
        return features
        
    except Exception as e:
        print(e)
        return [0] * 142

"""
 pe_att_ext = PEAttributeExtractor(bytez)
            # extract PE attributes
            atts = pe_att_ext.extract()
            # transform into a dataframe
            atts = pd.DataFrame([atts])
            model = app.config['model']

            # query the model
            result = model.predict_threshold(atts, threshold)[0]
            print('LABEL = ', result)
"""


def extract_features_2(file_path: str):
    bytez = open(file_path, "rb").read()
    pe_att_ext = PEAttributeExtractor(bytez)
    atts = pe_att_ext.extract()
    return atts

if __name__ == "__main__":
    file_path = "/root/ali/files/6b6975665e4e100dcba264eefb2c5e2032a0d97bf171b28688dc931b9e48988b.exe"
    features = extract_features_2(file_path)
    print(features)
