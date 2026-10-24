"""Bounded read-only/NX data exports in generated kernel PE providers."""
import struct
import pefile
from speakeasy.common import PERM_MEM_READ
from speakeasy.windows.loaders import ApiModuleLoader,SectionEntry


def add_readonly_exports(image,values,section_name,alignment=1):
    if image.name!='ntoskrnl' or not isinstance(image.loader,ApiModuleLoader):return None
    if not 1<=len(section_name.encode('ascii'))<=8 or alignment not in (1,4,8):
        raise ValueError('Invalid kernel data section layout')
    data=bytearray(image.regions[0].data)
    pe=pefile.PE(data=bytes(data),fast_load=True)
    rva=(max(image.image_size,len(data))+4095)&~4095
    header=pe.sections[-1].get_file_offset()+40
    if header+40>min(section.VirtualAddress for section in pe.sections):
        raise ValueError('Kernel headers have no room for kernel data section')
    data.extend(bytes(rva+4096-len(data)))
    struct.pack_into('<8sIIIIIIHHI',data,header,section_name.encode('ascii'),4096,rva,4096,rva,0,0,0,0,0x40000040)
    struct.pack_into('<H',data,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),pe.FILE_HEADER.NumberOfSections+1)
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),rva+4096)
    file_alignment=pe.OPTIONAL_HEADER.FileAlignment
    headers=max(pe.OPTIONAL_HEADER.SizeOfHeaders,(header+40+file_alignment-1)//file_alignment*file_alignment)
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfHeaders'),headers)
    export_rva=pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    ordinal_base,count,names=struct.unpack_from('<III',data,export_rva+16)
    functions_rva,names_rva,ordinals_rva=struct.unpack_from('<III',data,export_rva+28)
    # The upstream generator appends data names after sorted function names.
    # PE name lookup uses a sorted index; preserve each name/ordinal pair and
    # every function RVA while sorting that index, not the ordinal table.
    entries=[]
    for index in range(names):
        name_rva=struct.unpack_from('<I',data,names_rva+4*index)[0]
        end=data.find(b'\0',name_rva)
        if end<name_rva:
            raise ValueError('Unterminated generated kernel export name')
        name=bytes(data[name_rva:end])
        ordinal=struct.unpack_from('<H',data,ordinals_rva+2*index)[0]
        if ordinal>=count:
            raise ValueError('Generated kernel export ordinal is out of range')
        entries.append((name,name_rva,ordinal))
    for index,(_,name_rva,ordinal) in enumerate(sorted(entries)):
        struct.pack_into('<I',data,names_rva+4*index,name_rva)
        struct.pack_into('<H',data,ordinals_rva+2*index,ordinal)
    offset=0
    addresses={}
    for name,raw in values.items():
        offset=(offset+alignment-1)//alignment*alignment
        if not raw or offset+len(raw)>4096:raise ValueError('Kernel data export exceeds its bounded page')
        exported=next(item for item in image.exports if item.name==name)
        ordinal=exported.ordinal-ordinal_base
        if not 0<=ordinal<count:
            raise ValueError('Kernel data ordinal is out of range')
        struct.pack_into('<I',data,functions_rva+4*ordinal,rva+offset)
        data[rva+offset:rva+offset+len(raw)]=raw
        exported.address=image.image_base+rva+offset
        exported.execution_mode='native'
        addresses[name]=exported.address
        offset+=len(raw)
    image.image_size=rva+4096
    image.regions[0].data=bytes(data)
    image.sections.append(SectionEntry(section_name,rva,4096,PERM_MEM_READ))
    return image.image_base+rva,addresses
