#!/usr/bin/python3
"""Extracts Wii VC iso"""
import binascii
import sys
import getopt
import os
import shutil
from Crypto.Cipher import AES


PROMPT = '> '
WII_COMMON_KEY = '' # ...
WII_COMMON_KEY = str.encode(WII_COMMON_KEY)
CLUSTER_SIZE = 0x8000

def stick(content_folder, hif_file):
    """Sticks nfs files together"""
    hif_files = []
    for file in os.listdir(content_folder):
        if file.startswith("hif"):
            hif_files.append(os.path.join(content_folder, file))
    hif_files.sort()
    print('Found ' + str(len(hif_files)) + ' parts to reassemble')
    print('Beginning reassembly...')
    hif_obj = open(hif_file, 'wb')
    for file in hif_files:
        print('Reassembling ' + file)
        file_obj = open(file, 'rb')
        if file == hif_files[0]:
            file_obj.seek(0x200)
            print('Stripping first 200 bytes of the header')
        shutil.copyfileobj(file_obj, hif_obj)
        file_obj.close()
    hif_obj.close()
    print('hif file successfuly reconstructed')

def decrypt_nfs(key, in_filename, out_filename, chunksize=24*1024):
    """ Decrypts nfs file using htk"""

    ascii_key = binascii.hexlify(key).decode('ascii').upper()
    with open(in_filename, 'rb') as infile:
        initial_vector = 16 * '\x00'
        decryptor = AES.new(key, AES.MODE_CBC, initial_vector)
        with open(out_filename, 'wb') as outfile:
            print('\nDecrypting nfs file')
            print('Using ' + ascii_key + ' as key for decryption')
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    print('File successfully decrypted')
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.close()
        infile.close()

def gen_padding(file_obj, nbytes):
    """ Generates binary padding"""

    max_stack = 128000000
    while nbytes >= max_stack:
        padding = bytearray.fromhex('00' * 128000000)
        nbytes -= max_stack
        file_obj.write(padding)
    padding = bytearray.fromhex('00' * nbytes)
    file_obj.write(padding)

def write_cluster(infile_obj, outfile_obj, ncluster, data_offset, key):
    """Encrypts clusters and save them"""

    while ncluster >= 1:
        #print(str(ncluster) + ' clusters remaining')
        outfile_obj.write(infile_obj.read(0x3D0))
        initial_vector = infile_obj.read(0x10)
        outfile_obj.write(initial_vector)
        outfile_obj.write(infile_obj.read(0x20))
        sector = infile_obj.read(CLUSTER_SIZE-0x400)
        aes = AES.new(key, AES.MODE_CBC, initial_vector)
        sector = aes.encrypt(sector)
        outfile_obj.write(sector)
        ncluster -= 1

def make_iso(in_file, out_file):
    """ Create a valid Wii iso from the decrypted nfs file"""

    base_offset = 0xF800000

    with open(in_file, 'rb') as infile:
        with open(out_file, 'wb') as outfile:
            print('Beginning ISO creation...')

            # Header
            print('Generating header')
            outfile.write(infile.read(0x8000))

            # Padding up to VG table
            print('Padding up to the volume group table')
            gen_padding(outfile, 0x40000 - outfile.tell())

            # Generating valid VG table
            print('Generating a valid volume group table')
            outfile.write(bytearray.fromhex('00 00 00 01 00 01 00 08 00 00 00 00 00 00 00 00'))
            gen_padding(outfile, 0x10)
            infile.seek(0x8020)
            outfile.write(infile.read(0x10))

            # Padding up to region byte
            print('Padding up to the region byte')
            gen_padding(outfile, 0x4E003 - outfile.tell())

            infile.seek(0x16003)

            # Writing down region byte
            print('Writing down the region byte')
            outfile.write(infile.read(0x1))

            # Padding up to magic number
            print('Padding up to the magic number')
            gen_padding(outfile, 0x4FFFC - outfile.tell())

            infile.seek(0x17FFC)

            # Writing down magic number
            print('Writing down the magic number')
            outfile.write(infile.read(0x4))

            # Padding up to the unique partition
            print('Padding up to the unique partition, hang on...')
            gen_padding(outfile, base_offset - outfile.tell())

            infile.seek(0x18000)

            # Writing down partition up to the encrypted title key
            print('Writing down the partition up to the encrypted title key')
            outfile.write(infile.read(0x1BF))

            # Writing down encrypted title key
            print('Writing down encrypted title key')
            enc_title_key = infile.read(0x10)
            outfile.write(enc_title_key)

            # Filling up to the ticket id
            print('Filling up to the ticket id')
            outfile.write(infile.read(0xD))

            # Writing down title id
            print('Writing down title id')
            title_id = infile.read(0x8)
            outfile.write(title_id)

            # Writing down rest of ticket
            print('Writing down rest of the ticket')
            outfile.write(infile.read(0xC0))

            # Filling + getting data location and size
            print('Filling + getting data location and size')
            outfile.write(infile.read(0x14))

            data_offset = infile.read(0x4)
            outfile.write(data_offset)
            data_offset = int(binascii.hexlify(data_offset), 16)
            data_offset += base_offset

            data_size = infile.read(0x4)
            outfile.write(data_size)
            data_size = int(binascii.hexlify(data_size), 16)

            initial_vector = title_id[:8] + str.encode('\x00' * 8)
            title_decryptor = AES.new(WII_COMMON_KEY, AES.MODE_CBC, initial_vector)
            title_key = title_decryptor.decrypt(enc_title_key)

            ncluster = data_size / CLUSTER_SIZE
            write_cluster(infile, outfile, int(ncluster), data_offset, title_key)

            outfile.close()
        infile.close()

def routine(inputdir, outputdir):
    """Actions to be done in the script"""

    # Paths, files to be used
    content_folder = os.path.join(inputdir, 'content')
    htk_file = os.path.join(inputdir, 'code', 'htk.bin')
    hif_file = os.path.join(outputdir, 'hif.nfs.enc')
    dec_file = os.path.join(outputdir, 'hif.nfs.dec')
    iso_name = inputdir + '.iso'
    iso_file = os.path.join(outputdir, iso_name)

    try:
        htk_obj = open(htk_file, 'rb')
    except FileNotFoundError:
        print('htk.bin missing')
    key = htk_obj.read()

    # Reassembles nfs file
    stick(content_folder, hif_file)

    # Decrypts iso
    decrypt_nfs(key, hif_file, 'hif.nfs.dec')

    # Makes valid Wii iso
    make_iso(dec_file, iso_file)

def main(argv):
    """Bootstraps script"""
    inputdir = ''
    outputdir = ''
    errormsg = 'Usage : wii_vc_extract.py -i <inputdir> -o <outputdir>'
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print(errormsg)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('wiiu2wii.py -i <inputdir> -o <outputdir>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputdir = arg
        elif opt in ("-o", "--ofile"):
            outputdir = arg
    if inputdir == '':
        print(errormsg)
        sys.exit(2)
    else:
        routine(inputdir, outputdir)

if __name__ == "__main__":
    main(sys.argv[1:])
