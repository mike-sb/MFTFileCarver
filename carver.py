import mmap
from struct import unpack
from datetime import datetime
import argparse

def parseTimestamp(ts_bytes):

    bytes_low = unpack('<L', ts_bytes[0:4])[0]
    bytes_high = unpack('<L', ts_bytes[4:8])[0]
    try:
        return str(datetime.utcfromtimestamp((float(bytes_high) * 2 ** 32 + bytes_low) * 1e-7 - 11644473600))
    except:
        return "corrupt"

def parseData(mftentry):

    # locate header for Data attribute
    data_entry_offset = mftentry.find(b'\x80\x00\x00\x00')

    # if there is no Data return and proceed. Seems to be a broken entry
    if data_entry_offset == -1: return -21;

    # calculate some offsets to check plausibility

    length_of_attribute_byte = mftentry[data_entry_offset + 4: data_entry_offset + 8]  # 4 bytes little endian

    # problem parsing length
    if len(length_of_attribute_byte) < 4:
        # print("Length: "+str(len(length_of_attribute_byte)))
        return -22

    # get length_of_attribute
    length_of_attribute = unpack('<I', length_of_attribute_byte)[0]



    # only accept realistic values, min should be int 89, maximum i'll put at int 1024 for now
    if length_of_attribute < 50 or length_of_attribute > 1024:
        # print("Length: "+str(length_of_attribute))
        return -23
    strin_data= str(mftentry[data_entry_offset + 8]) 
    resident = ord(strin_data)
    resident_data = 0
    if resident == 0: # 0 means it is resident. Microsoft seems to have a strange take on boolean
        resident_data = mftentry[data_entry_offset+64:data_entry_offset+length_of_attribute]

    return resident_data

def parseFN(mftentry):


    last_attribute_pointer = 0;
    last_attribute_size = 0;
    names = []
    return_code = -1

    
        # locate header for File_Name attribute
    file_entry_offset = mftentry.find(b"\x30\x00\x00\x00", last_attribute_pointer + last_attribute_size)
    # print("ENTRY OF FN:" + str(file_entry_offset))
        # if there is no FN return and proceed. Seems to be a broken entry
    if file_entry_offset == -1: return -10


    length_of_attribute_byte = mftentry[file_entry_offset + 4: file_entry_offset + 8]  # 4 bytes little endian
    # print("Length: "+str(len(length_of_attribute_byte)))
    # problem parsing length
    if len(length_of_attribute_byte) < 4:
            
            return_code = -2
            last_attribute_pointer = file_entry_offset
            last_attribute_size = 90



        # get length_of_attribute
    length_of_attribute = unpack('<I', length_of_attribute_byte)[0]
    # print("length_of_attribute: "+str(length_of_attribute))
        # only accept realistic values, min should be int 89, maximum i'll put at int 1024 for now
    if length_of_attribute < 90: #or length_of_attribute > 1024
            print(length_of_attribute) 
            return -3   # if the first entry is already broken it does not make sense to scan for other after that

        # check if long or short. broken if not x01 or x02
    try:
            fn_type = mftentry[file_entry_offset + 89]
            if fn_type != 1 and fn_type != 2:
                # print ("FN Type: "+str(fn_type))
                return_code = -4
                last_attribute_pointer = file_entry_offset
                last_attribute_size = length_of_attribute
                
    except Exception as err:
            print ("Error parseFN: {}".format(err))
            return_code = -4
            last_attribute_pointer = file_entry_offset
            last_attribute_size = length_of_attribute
            
   
    fn_length_offset=str(mftentry[file_entry_offset + 88])
    if len(fn_length_offset) > 1:
        fn_length = ord(fn_length_offset[0]) * 2 # it's character count not bytecount and utf16 so multiply by 2
    else:
        fn_length = ord(fn_length_offset) * 2

    # print("fn_length: "+str(fn_length))
    namestring = mftentry[file_entry_offset + 90:file_entry_offset + 90 + fn_length]
   
        # prepare for next round
    last_attribute_pointer = file_entry_offset
    last_attribute_size = length_of_attribute


    try:
            names.append(namestring.decode("UTF-16LE"))
        # names.append(namestring.decode(encoding="utf-8"))
    except:
            names.append("corrupt: len=" + str(len(names)))
    
    if len(names) == 0: return return_code;
    return names
    

def parseSTDInfo(mftentry):


    # locate header for STD_Info attribute
    std_entry_offset = mftentry.find(b'\x10\x00\x00\x00')
    # print(std_entry_offset)
    # if there is no STD_Info return and proceed. Seems to be a broken entry
    if std_entry_offset == -1: return -31,"corrupt","corrupt","corrupt","corrupt";

    # calculate some offsets to check plausibility

    length_of_attribute_byte = mftentry[std_entry_offset + 4: std_entry_offset + 8]  # 4 bytes little endian

    # problem parsing length
    if len(length_of_attribute_byte) < 4:
        # print("Length: "+str(len(length_of_attribute_byte)))
        return -32,"corrupt","corrupt","corrupt","corrupt"

    # get length_of_attribute
    length_of_attribute = unpack('<I', length_of_attribute_byte)[0]

    # only accept realistic values, min should be int 89,
    if length_of_attribute < 30 or length_of_attribute > 1024:
        # print length_of_attribute
        return -33,"corrupt","corrupt","corrupt","corrupt"

    # timestamps
    creation_time_bytes = mftentry[std_entry_offset + 24: std_entry_offset + 32]
    creation_time = parseTimestamp(creation_time_bytes)

    modification_time_bytes = mftentry[std_entry_offset + 32: std_entry_offset + 40]
    modification_time = parseTimestamp(modification_time_bytes)

    metachange_time_bytes = mftentry[std_entry_offset + 40: std_entry_offset + 48]
    metachange_time = parseTimestamp(metachange_time_bytes)

    access_time_bytes = mftentry[std_entry_offset + 48: std_entry_offset + 56]
    access_time = parseTimestamp(access_time_bytes)

    return 0,creation_time,modification_time,metachange_time,access_time

def parse_entry (start_offset,end_offset, mm):
    mm.seek(start_offset)
    mftentry = mm.read((end_offset-start_offset)+4)
    mm.seek(start_offset+4)

    fname = parseFN(mftentry)
    if type(fname)==type(0) and fname < 0:
        return fname 
    stdinfo = parseSTDInfo(mftentry)
    data = parseData(mftentry)

    if data < 0:
        data = "data attribute corrupt"
    elif data == 0:
        data = "not resident"
    else:
        data = data.hex()

    try:
        print('{};{};{};{};{};{};'.format(fname[0] ,stdinfo[1],stdinfo[2],stdinfo[3],stdinfo[4],data))
    except Exception as err:
        print ("Error parse_entry: {}".format(err))

    # if 



    return 0

def load_and_start(filename):
    # Open File
    try:
        with open(filename, "r+b") as f:

            file_pos_pointer = 0
            file_end_pointer = 0
            mm = mmap.mmap(f.fileno(), 0)

               # statistics
            allhits = 0
            no_fn = 0
            attr_len = 0
            unlikely_bounds = 0
            parsed = 0
            no_type = 0
            while 1:

                file_pos_pointer = mm.find(b'\x46\x49\x4C\x45',file_pos_pointer)
                if file_pos_pointer == -1: break

                file_end_pointer =  mm.find(b'\xFF\xFF\xFF\xFF',file_end_pointer)
                if file_end_pointer == -1: 
                    file_end_pointer=file_end_pointer+1024
                # print(file_pos_pointer)

                # print(file_end_pointer)
                # data = mm[file_pos_pointer:file_end_pointer+4]
                # hex_data = " ".join("{:02X}".format(c) for c in data )
                
                # print(hex_data)

                print("filenames;STD created;STD modified;STD Meta modified;STD accessed;data;")
                res = parse_entry(file_pos_pointer,file_end_pointer, mm)
                allhits = allhits + 1
                if type(res)==type(0): 
                    if res == -1:
                        no_fn = no_fn + 1
                    if res == -2:
                        attr_len = attr_len + 1
                    if res == -3:
                        unlikely_bounds = unlikely_bounds + 1
                    if res == -4:
                        no_type = no_type + 1
                    if res ==  0:
                        parsed = parsed + 1
                file_pos_pointer = file_pos_pointer + file_end_pointer
                


        print("++++++++++++++++++++++++++++++++++++++++++++++")
        print ("+                    Stats                   +")
        print ("++++++++++++++++++++++++++++++++++++++++++++++")
        print ("Total processed : "+ str(allhits) )
        print ("No $FN          : "+ str(no_fn))
        print ("No $FN Type     : "+ str(no_type))
        print ("Unlikely Bounds : "+ str(unlikely_bounds))
        print ("Other           : "+ str(attr_len))
        print ("==============================================")
        print ("Parsed          : "+ str(parsed))
    except Exception as err:
        print ("Error: {}".format(err))
        print ("Input file {} not found".format(filename))

parser = argparse.ArgumentParser(description='Carving file entries from images/ dumps/ byles. Recovers FN atr, giving std info. Inspired by github@cyb3rfox.')
parser.add_argument('filename',help='path to file')

args = parser.parse_args()

filename =  args.filename #filename = r"./$MFT"

load_and_start(filename)
