import time
import sys
import os
import navegador as nave
import websocket
from websocket import create_connection
import urllib
import re
import random
import binascii
import zlib
import math

filter_methods = {0: {'type': {0: None, 1: 'Sub', 2: 'Up', 3: 'Average', 4: 'Paeth', None: 0, 'Up': 2, 'Average': 3, 'Sub': 1, 'Paeth': 4}}}

# fd = open('C:/Users/dapeng/Desktop/PNG/plate_png/plate_PNG5318.png','rb+')

fd = open('C:/Users/dapeng/Desktop/PNG/t1.png','rb+')
content = fd.read()
fd.close()


def bytes_to_dec(b):
    d = binascii.hexlify(b)
    d = int(d,16)
    return(d)

def dec_to_bytes(d):
    s = "{0:0>8x}".format(d)
    b=binascii.unhexlify(s)
    return(b)

def get_signature(content):
    rslt = {}
    rslt['signature_bytes'] = content[0:8]
    rslt['signature_hex_format_bytes'] = binascii.hexlify(signature_bytes)
    rslt['unhandled_bytes'] = content[8:]
    print(rslt['signature_hex_format_bytes'])
    return(rslt)

def get_type_attrs(type_name):
    type_attrs = {}
    fb = type_name.encode('utf-8')[0]
    ancillary_bit = fb & 0x20
    ancillary_bit = ancillary_bit >> 5
    if(ancillary_bit):
        type_attrs['ancillary'] = 1
        type_attrs['critical'] = 0
        print('ancillary,lowercase')
    else:
        type_attrs['ancillary'] = 0
        type_attrs['critical'] = 1
        print('critical,uppercase')
    pb = type_name.encode('utf-8')[1]
    private_bit = pb & 0x20
    private_bit = private_bit >> 5
    if(private_bit):
        type_attrs['private'] = 1
        type_attrs['public'] = 0
        print('private,lowercase')
    else:
        type_attrs['private'] = 0
        type_attrs['public'] = 1
        print('public,uppercase')
    rb = type_name.encode('utf-8')[2]
    reserved_bit = rb & 0x20
    reserved_bit = reserved_bit >> 5
    if(reserved_bit):
        type_attrs['reserved'] = 1
        type_attrs['unreserved'] = 0
        print('reserved,lowercase,this bit should not be reserved')
    else:
        type_attrs['reserved'] = 0
        type_attrs['unreserved'] = 1
        print('unreserved,uppercase')
    stcb = type_name.encode('utf-8')[1]
    safe_to_copy_bit = stcb & 0x20
    safe_to_copy_bit = safe_to_copy_bit >> 5
    if(safe_to_copy_bit):
        type_attrs['Safe-to-copy'] = 1
        type_attrs['Unsafe-to-copy'] = 0
        print('safe to copy,lowercase')
    else:
        type_attrs['Safe-to-copy'] = 0
        type_attrs['Unsafe-to-copy'] = 1
        print('Unsafe to copy,uppercase')
    return(type_attrs)

def get_all_chunks(unhandled_bytes):
    chunks = []
    cursor = 0
    while(cursor < unhandled_bytes.__len__()):
        chunk = {}
        chunk_length_bytes = unhandled_bytes[cursor:(cursor+4)]
        chunk_length_dec = bytes_to_dec(chunk_length_bytes)
        chunk_type_bytes = unhandled_bytes[(cursor+4):(cursor+8)]
        chunk_type_string = chunk_type_bytes.decode('utf-8')
        chunk_content_bytes = unhandled_bytes[(cursor+8):(cursor+8+chunk_length_dec)]
        chunk_crc_bytes = unhandled_bytes[(cursor+8+chunk_length_dec):(cursor+8+chunk_length_dec + 4)]
        chunk['TD'] = unhandled_bytes[(cursor+4):(cursor+8+chunk_length_dec)]
        chunk['Length'] = chunk_length_dec
        chunk['Chunk Type'] = chunk_type_string
        chunk['Chunk Data'] = chunk_content_bytes
        chunk['CRC'] = chunk_crc_bytes
        if(chunk['CRC'] == dec_to_bytes(zlib.crc32(chunk['TD']))):
            chunk['verified'] = 1
        else:
            chunk['verified'] = 0
        chunks.append(chunk)
        cursor = cursor+8+chunk_length_dec + 4
    return(chunks)

def print_all_chunks_crc(chunks):
    for i in range(0,chunks.__len__()):
        print('chunk:{0} type:{1}'.format(i,chunks[i]['CRC']))

def print_all_chunks_verified(chunks):
    for i in range(0,chunks.__len__()):
        print('chunk:{0} type:{1}'.format(i,chunks[i]['verified']))

def print_all_chunks_type(chunks):
    for i in range(0,chunks.__len__()):
        print('chunk:{0} type:{1}'.format(i,chunks[i]['Chunk Type']))

def print_IHDR_color_type(color_type):
    if(color_type == 0):
        print('    grayscale without alpha')
    elif(color_type == 2):
        print('    true color without alpha')
    elif(color_type == 3):
        print('    indexed color')
    elif(color_type == 4):
        print('    grayscale with alpha')
    elif(color_type == 6):
        print('    true color with alpha')
    else:
        print('    not valid color type')

def decode_color_type(color_type):
    color_type = {}
    color_type['palette used'] = color_type & 0x0000001
    color_type['color used'] = (color_type & 0x0000010) >> 1
    color_type['alpha channel used'] = (color_type & 0x0000100) >> 2
    return(color_type)


def get_allowed_bit_depth_via_color_type(color_type):
    allowed_bit_depth = []
    if(color_type == 0):
        allowed_bit_depth = [1,2,4,8,16]
        print('    Each pixel is a grayscale sample')
    elif(color_type == 2):
        allowed_bit_depth = [8,16]
        print('    Each pixel is an R,G,B triple')
    elif(color_type == 3):
        allowed_bit_depth = [1,2,4,8]
        print('    Each pixel is a palette index;a PLTE chunk must appear.')
    elif(color_type == 4):
        allowed_bit_depth = [8,16]
        print('    Each pixel is a grayscale sample,followed by an alpha sample.')
    elif(color_type == 6):
        allowed_bit_depth = [8,16]
        print('    Each pixel is an R,G,B triple,followed by an alpha sample')
    else:
        print('    not valid color type')
    return(allowed_bit_depth)

def print_compression_method(compression_method):
    if(compression_method == 0):
        print("    deflate/inflate compression with a 32Ksliding window")
    else:
        print("    not valid compression method")

def print_filter_method(filter_method):
    if(filter_method == 0):
        print("    adaptive filter with five basic filter types")
    else:
        print("    not valid filter method")   

def print_interlace_method(interlace_method):
    if(interlace_method == 0):
        print("    no interlace")
    elif(interlace_method == 1):
        print("    Adam7 interlace")
    else:
        print("    not valid interlace method")         

def decode_IHDR(IHDR_content_bytes):
    '''Image header'''
    IHDR = {}
    IHDR['Width'] = bytes_to_dec(IHDR_content_bytes[0:4])
    print('Width:{0}'.format(IHDR['Width']))
    IHDR['Height'] = bytes_to_dec(IHDR_content_bytes[4:8])
    print('Height:{0}'.format(IHDR['Height']))
    IHDR['Bit depth'] = IHDR_content_bytes[8]
    print("Bit depth:{0}".format(IHDR['Bit depth']))
    IHDR['Color type'] = IHDR_content_bytes[9]
    print("Color type:{0}".format(IHDR['Color type']))
    print_IHDR_color_type(IHDR['Color type'])
    allowed_bit_depth_array = get_allowed_bit_depth_via_color_type(IHDR['Color type'])
    if(IHDR['Bit depth'] in allowed_bit_depth_array):
        pass
    else:
        print('Bit depth {0} is not valid for Color type {1}'.format(IHDR['Bit depth'],IHDR['Color type']))
    IHDR['Compression method'] = IHDR_content_bytes[10]
    print('Compression method:{0}'.format(IHDR['Compression method']))
    print_compression_method(IHDR['Compression method'])
    IHDR['Filter method'] = IHDR_content_bytes[11]
    print('Filter method:{0}'.format(IHDR['Filter method']))
    print_filter_method(IHDR['Filter method'])
    IHDR['Interlace method'] = IHDR_content_bytes[12]
    print('Interlace method:{0}'.format(IHDR['Interlace method']))
    print_interlace_method(IHDR['Interlace method'])
    return(IHDR)

def decode_iCCP(iCCP_content_bytes):
    '''When the iCCP chunk is present, applications that recognize it and are capable of color management [ICC] should ignore the gAMA and cHRM chunks and use the iCCP chunk instead, but applications incapable of full-fledged color management should use the gAMA and cHRM chunks if present.'''
    iCCP = {}
    arr = iCCP_content_bytes.split(b'\x00')
    iCCP['Profile name'] = arr[0]
    profile_name_len = iCCP['Profile name'].__len__()
    iCCP['Profile name'] = arr[0].decode('utf-8')
    iCCP['Compression method'] = iCCP_content_bytes[profile_name_len+1]
    iCCP['Compressed profile'] = iCCP_content_bytes[(profile_name_len+2):]
    if(iCCP['Compression method'] == 0):
        iCCP['profile'] = zlib.decompress(iCCP['Compressed profile'])
    return(iCCP)


def decode_cHRM(cHRM_content_bytes):
    '''Primary chromaticities and white point'''
    cHRM = {}
    cHRM['White Point x'] = bytes_to_dec(cHRM_content_bytes[0:4])
    print('White Point x:{0}'.format(cHRM['White Point x']))
    cHRM['White Point y'] = bytes_to_dec(cHRM_content_bytes[4:8])
    print('White Point y:{0}'.format(cHRM['White Point y']))
    cHRM['Red x'] = bytes_to_dec(cHRM_content_bytes[8:12])
    print('Red x:{0}'.format(cHRM['Red x']))
    cHRM['Red y'] = bytes_to_dec(cHRM_content_bytes[12:16])
    print('Red y:{0}'.format(cHRM['Red y']))
    cHRM['Green x'] = bytes_to_dec(cHRM_content_bytes[16:20])
    print('Green x:{0}'.format(cHRM['Green x']))
    cHRM['Green y'] = bytes_to_dec(cHRM_content_bytes[20:24])
    print('Green y:{0}'.format(cHRM['Green y']))
    cHRM['Blue x'] = bytes_to_dec(cHRM_content_bytes[24:28])
    print('Blue x:{0}'.format(cHRM['Blue x']))
    cHRM['Blue y'] = bytes_to_dec(cHRM_content_bytes[28:32])
    print('Blue y:{0}'.format(cHRM['Blue y']))
    return(cHRM)

def decode_bKGD(bKGD_content_bytes,color_type):
    '''Background color'''
    bKGD = {}
    if(color_type == 3):
        bKGD['Palette index'] = bKGD_content_bytes[0]
        print('Palette index:{0}'.format(bKGD['Palette index']))
    elif((color_type == 0) | (color_type == 4) ):
        bKGD['Grey'] = bytes_to_dec(bKGD_content_bytes[0:2])
        print('Grey:{0}'.format(bKGD['Palette index']))
    elif((color_type == 2) | (color_type == 6) ):
        bKGD['Red'] = bytes_to_dec(bKGD_content_bytes[0:2])
        bKGD['Green'] = bytes_to_dec(bKGD_content_bytes[2:4])
        bKGD['Blue'] = bytes_to_dec(bKGD_content_bytes[4:6])
        print('Red:{0}'.format(bKGD['Red']))
        print('Green:{0}'.format(bKGD['Green']))
        print('Blue:{0}'.format(bKGD['Blue']))
    else:
        pass
    return(bKGD)

def print_pHYs_unit_specifier(unit_specifier):
    if(unit_specifier == 0):
        print("     unit is unknown,When the unit specifier is 0, the pHYs chunk defines pixel aspect ratio only; the actual size of the pixels remains unspecified.")
    elif(unit_specifier == 1):
        print("     unit is the meter,Conversion note: one inch is equal to exactly 0.0254 meters")
    else:
        print("    not Valid unit specifier")


def decode_pHYs(pHYs_content_bytes):
    '''Physical pixel dimensions'''
    pHYs = {}
    pHYs['Pixels per unit, X axis'] = bytes_to_dec(pHYs_content_bytes[0:4])
    print('Pixels per unit, X axis:{0}'.format(pHYs['Pixels per unit, X axis']))
    pHYs['Pixels per unit, Y axis'] = bytes_to_dec(pHYs_content_bytes[4:8])
    print('Pixels per unit, Y axis:{0}'.format(pHYs['Pixels per unit, Y axis']))
    pHYs['Unit specifier'] = pHYs_content_bytes[8]
    print('Unit specifier:{0}'.format(pHYs['Unit specifier']))
    print_pHYs_unit_specifier(pHYs['Unit specifier'])
    return(pHYs)

def decode_vpAg(vpAg_content_bytes):
    vpAg = {}
    vpAg['VirtualImageWidth'] = bytes_to_dec(vpAg_content_bytes[0:4]) 
    print('VirtualImageWidth:{0}'.format(vpAg['VirtualImageWidth']))
    vpAg['VirtualImageHeight'] = bytes_to_dec(vpAg_content_bytes[4:8])
    print('VirtualImageHeight:{0}'.format(vpAg['VirtualImageHeight']))
    vpAg['VirtualPageUnits'] = vpAg_content_bytes[8]
    print('VirtualPageUnits:{0}'.format(vpAg['VirtualPageUnits']))
    return(vpAg)


def decode_tEXt(tEXt_content_bytes):
    tExt = {}
    arr = tEXt_content_bytes.split(b'\x00')
    tExt['Keyword'] = arr[0].decode('utf-8')
    tExt['Text'] = arr[1].decode('utf-8')
    print("{0}:{1}".format(tExt['Keyword'],tExt['Text']))
    return(tExt)

def get_the_whole_compressed_bytes_from_IDATs(chunks):
    rslt = []
    for i in range(0,chunks.__len__()):
        if(chunks[i]['Chunk Type'] == 'IDAT'):
            rslt.append(chunks[i]['Chunk Data'])
    print("the whole length:{0}".format(the_whole_compressed_bytes.__len__()))
    return(b''.join(rslt))

def get_each_pixel_bytes(bit_depth,color_type):
    rslt = {}
    rslt['s'] = 0;
    rslt['m'] = 0
    if(color_type == 0):
        if(bit_depth >= 8):
            rslt['m'] = int(bit_depth/8)
        else:
            rslt['s'] = int(8/bit_depth)
    elif(color_type == 2):
        rslt['m'] = int(bit_depth/8 * 3)
    elif(color_type == 3):
        if(bit_depth >= 8):
            rslt['m'] = int(bit_depth/8)
        else:
            rslt['s'] = int(8/bit_depth)
    elif(color_type == 4):
        rslt['m'] = int(bit_depth/8 * 2)
    elif(color_type == 6):
        rslt['m'] = int(bit_depth/8 * 4)
    else:
        pass
    return(rslt)

def get_all_filtered_scanlines(the_whole_uncompressed_filtered_bytes,height,width,each_pixel_bytes):
    all_filtered_scanlines = []
    cursor = 0
    interval = width * each_pixel_bytes + 1
    for i in range(0,height):
        all_filtered_scanlines.append(the_whole_uncompressed_filtered_bytes[cursor:(cursor+interval)])
        cursor = cursor+interval
    return(all_filtered_scanlines)


def get_bpp(color_type,bit_depth):
    if(color_type == 0):
        return(math.ceil(bit_depth/8))
    elif(color_type == 2):
        return(math.ceil(bit_depth/8 * 3))
    elif(color_type == 3):
        print('    need refer to plette')
    elif(color_type == 4):
        return(math.ceil(bit_depth/8 * 2))
    elif(color_type == 6):
        return(math.ceil(bit_depth/8 * 4))
    else:
        return(0)


def paeth_predictor(raw_x_sub_bpp,prior,prior_x_sub_bpp);
    p = raw_x_sub_bpp + prior + prior_x_sub_bpp
    pa = math.fabs(p - raw_x_sub_bpp)
    pb = math.fabs(p - prior)
    pc = math.fabs(p - prior_x_sub_bpp)
    if( (pa <= pb) & (pa <= pc)):
        return(raw_x_sub_bpp)
    elif(pb <= pc):
        return(prior)
    else:
        return(prior_x_sub_bpp)


def unfilter(filter_method,bpp,filtered_line,prior_filtered_line,filter_methods):
    filter_method_0_type_dict = filter_methods[0]['type']
    filter_type = filtered_line[0]
    filtered_content = filtered_line[1:]
    prior_filtered_content = prior_filtered_line[1:]
    count = filtered_content.__len__()
    prior_count = prior_filtered_content.__len__()
    unfiltered_line = b''
    if(filter_method == 0):
        if(filter_type == filter_method_0_type_dict[None]):
            unfiltered_line = filtered_content
        elif(filter_type == filter_method_0_type_dict['Up']):
            '''On the first scanline of an image (or of a pass of an interlacedimage), assume Prior(x) = 0 for all x'''
            prior_array = []
            up_array = []
            raw_array = []
            raw_byte_array =[]
            for i in range(0,prior_count):
                prior_array.append(prior_filtered_content[i])
            for i in range(0,count):
                up_array.append(filtered_content[i])
            for i in range(0,count):
                prior = prior_array[i]
                up = up_array[i]
                raw = prior + up
                raw = raw % 256
                raw_array.append(raw)
            for i in range(0,count):
                raw = raw_array[i]
                raw_byte_array.append(chr(raw).encode('utf-8'))
            unfiltered_line = unfiltered_line.join(raw_byte_array)            
        elif(filter_type == filter_method_0_type_dict['Average']):
            '''The Average filter uses the average of the two neighboring pixels(left and above) to predict the value of a pixel.'''
            prior_array = []
            average_array = []
            raw_array = []
            raw_byte_array =[]
            for i in range(0,prior_count):
                prior_array.append(prior_filtered_content[i])
            for i in range(0,count):
                average_array.append(filtered_content[i])
            for i in range(0,count):
                average = average_array[i]
                prior = prior_array[i]
                index = i - bpp
                if(index <0):
                    raw_x_sub_bpp = 0
                else:
                    raw_x_sub_bpp = raw_array[index]
                raw = average + math.floor((raw_x_sub_bpp+prior)/2)
                raw = raw % 256
                raw_array.append(raw)
            for i in range(0,count):
                raw = raw_array[i]
                raw_byte_array.append(chr(raw).encode('utf-8'))
            unfiltered_line = unfiltered_line.join(raw_byte_array)
        elif(filter_type == filter_method_0_type_dict['Sub']):
            raw_array = []
            sub_array = []
            raw_byte_array =[]
            for i in range(0,count):
                sub_array.append(filtered_content[i])
            for i in range(0,count):
                sub = sub_array[i]
                index = i - bpp
                if(index <0):
                    raw_x_sub_bpp = 0
                else:
                    raw_x_sub_bpp = raw_array[index]
                raw = sub + raw_x_sub_bpp
                raw = raw % 256
                raw_array.append(raw)
            for i in range(0,count):
                raw = raw_array[i]
                raw_byte_array.append(chr(raw).encode('utf-8'))
            unfiltered_line = unfiltered_line.join(raw_byte_array)
        elif(filter_type == filter_method_0_type_dict['Paeth']):
            prior_array = []
            paeth_array = []
            raw_array = []
            raw_byte_array =[]
            for i in range(0,prior_count):
                prior_array.append(prior_filtered_content[i])
            for i in range(0,count):
                paeth_array.append(filtered_content[i])
            for i in range(0,count):
                paeth = paeth_array[i]
                index = i - bpp
                if(index <0):
                    raw_x_sub_bpp = 0
                else:
                    raw_x_sub_bpp = raw_array[index]
                prior = prior_array[i]
                if(index <0):
                    prior_x_sub_bpp = 0
                else:
                    prior_x_sub_bpp = prior_array[index]
                raw = paeth + paeth_predictor(raw_x_sub_bpp,prior,prior_x_sub_bpp)
                raw = raw % 256
                raw_array.append(raw)
            for i in range(0,count):
                raw = raw_array[i]
                raw_byte_array.append(chr(raw).encode('utf-8'))
            unfiltered_line = unfiltered_line.join(raw_byte_array)
        else:
            print("method 0 only have 5 filter types : None,Sub,Up,Average,Paeth")
    else:
        print("other methods not implemented yet")
    return(unfiltered_line)


signature =  get_signature(content)['signature_hex_format_bytes']
unhandled_bytes =  get_signature(content)['unhandled_bytes']
chunks = get_all_chunks(unhandled_bytes)
print_all_chunks_type(chunks)
IHDR_content_bytes = chunks[0]['Chunk Data']
IHDR = decode_IHDR(IHDR_content_bytes)
color_type = IHDR['Color type']



cHRM_content_bytes = chunks[1]['Chunk Data']
cHRM = decode_cHRM(cHRM_content_bytes)
bKGD_content_bytes = chunks[2]['Chunk Data']
bKGD = decode_bKGD(bKGD_content_bytes,color_type)
pHYs_content_bytes = chunks[3]['Chunk Data']
pHYs = decode_pHYs(pHYs_content_bytes)
vpAg_content_bytes = chunks[4]['Chunk Data']
vpAg = decode_vpAg(vpAg_content_bytes)

def decode_pixel(raw_pixel,bit_depth,color_type):
    pixel = {}
    len = raw_pixel.__len__()
    if(color_type == 0):
        pixel['greyscale'] = bytes_to_dec(raw_pixel)
    elif(color_type == 2):
        interval = len // 3
        pixel['R'] = bytes_to_dec(raw_pixel[0:interval])
        pixel['G'] = bytes_to_dec(raw_pixel[interval:(interval * 2)])
        pixel['B'] = bytes_to_dec(raw_pixel[(interval * 2):(interval * 3)])
    elif(color_type == 3):
        # if(bit_depth ==1):
        # elif(bit_depth ==2):
        # elif(bit_depth ==4):
        # elif(bit_depth ==8):
        print('    need refer to plette')
    elif(color_type == 4):
        interval = len // 2
        pixel['greyscale'] = bytes_to_dec(raw_pixel[0:interval])
        pixel['alpha'] = bytes_to_dec(raw_pixel[interval:(interval * 2)])
    elif(color_type == 6):
        interval = len // 4
        pixel['R'] = bytes_to_dec(raw_pixel[0:interval])
        pixel['G'] = bytes_to_dec(raw_pixel[interval:(interval * 2)])
        pixel['B'] = bytes_to_dec(raw_pixel[(interval * 2):(interval * 3)])
        pixel['alpha'] = bytes_to_dec(raw_pixel[(interval * 3):(interval * 4)])
    else:
        print("not supported color_type")
    return(pixel)

def get_raw_pixels_array(IHDR,chunks,filter_methods):
    filter_method_0_type_dict = filter_methods[0]['type']
    pixels = {}
    for i in range(0,IHDR['Height']):
        pixels[i] = {}
    the_whole_compressed_bytes = get_the_whole_compressed_bytes_from_IDATs(chunks)
    the_whole_uncompressed_filtered_bytes = zlib.decompress(the_whole_compressed_bytes)
    each_pixel_bytes = get_each_pixel_bytes(IHDR['Bit depth'],IHDR['Color type'])
    all_filtered_scanlines = get_all_filtered_scanlines(the_whole_uncompressed_filtered_bytes,IHDR['Height'],IHDR['Width'],each_pixel_bytes)
    bpp = get_bpp(IHDR['Color type'],IHDR['Bit depth'])
    prior_filtered_line = b'\x00' * IHDR['Width']
    if(each_pixel_bytes['s'] == 0):
        for i in range(0,all_filtered_scanlines.__len__()):
            filtered_line = all_filtered_scanlines[i]
            unfiltered_line = unfilter(IHDR['Filter method'],bpp,filtered_line,prior_filtered_line)
            cursor = 0
            for j in range(0,IHDR['Width']):
                pixels[i][j] = unfiltered_line[cursor:(cursor+each_pixel_bytes['m'])]
                cursor = cursor + each_pixel_bytes['m']
            prior_filtered_line = filtered_line
    else:
        for i in range(0,all_filtered_scanlines.__len__()):
            filtered_line = all_filtered_scanlines[i]
            unfiltered_line = unfilter(IHDR['Filter method'],bpp,filtered_line,prior_filtered_line)
            cursor = 0
            while(cursor < unfiltered_line.__len__()):
                sb =  unfiltered_line[cursor];
                if(each_pixel_bytes['s'] == 8):
                    j = cursor;
                    pixels[i][j] = dec_to_bytes(sb >> 7)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x40) >> 6)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x20) >> 5)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x10) >> 4)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x08) >> 3)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x04) >> 2)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x02) >> 1)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes(sb & 0x01)
                elif(each_pixel_bytes['s'] == 4):
                    j = cursor;
                    pixels[i][j] = dec_to_bytes(sb >> 6)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x30) >> 4)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes((sb & 0x0c) >> 2)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes(sb & 0x03)
                elif(each_pixel_bytes['s'] == 2):
                    j = cursor;
                    pixels[i][j] = dec_to_bytes(sb >> 4)
                    j = j + 1;
                    pixels[i][j] = dec_to_bytes(sb & 0x0f)
                else:
                    print("impossible!!!")
                cursor = cursor + 1
            prior_filtered_line = filtered_line
    return(pixels)

def format_pixels_array(pixels,IHDR):
    for i in range(0,pixels.__len__()):
        for j in range(0,pixels[i].__len__()):
            pixels[i][j] = decode_pixel(pixels[i][j],IHDR['Bit depth'],IHDR['Color type'])
    return(pixels)






