#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2021 ArtInChip Technology Co., Ltd
# Dehuang Wu <dehuang.wu@artinchip.com>

import os, sys, subprocess, math, re, zlib, json, struct, argparse
from collections import namedtuple
from collections import OrderedDict
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import MD5
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Signature import PKCS1_v1_5

DATA_ALIGNED_SIZE = 2048
META_ALIGNED_SIZE = 512
BURNER = False # Whether or not to generate the image used by the burner
VERBOSE = False

def parse_image_cfg(cfgfile):
    """ Load image configuration file
    Args:
        cfgfile: Configuration file name
    """
    with open(cfgfile, "r") as f:
        lines = f.readlines()
        jsonstr = ""
        for line in lines:
            sline = line.strip()
            if sline.startswith("//"):
                continue
            slash_start = sline.find("//")
            if slash_start > 0:
                jsonstr += sline[0:slash_start]
            else:
                jsonstr += sline
        # Use OrderedDict is important, we need to iterate FWC in order.
        jsonstr = jsonstr.replace(",}", "}").replace(",]", "]")
        cfg = json.loads(jsonstr, object_pairs_hook=OrderedDict)
    return cfg

def get_file_path(path, alternate_dir):
    if os.path.exists(alternate_dir + path):
        return alternate_dir + path
    if os.path.exists(path):
        return path
    return None

def aic_boot_get_resource_file_size(cfg, keydir, datadir):
    """ Get size of all resource files
    """
    files = {}
    filepath = ""
    if "resource" in cfg:
        if "private" in cfg["resource"]:
            filepath = get_file_path(cfg["resource"]["private"], keydir)
            if filepath == None:
                filepath = get_file_path(cfg["resource"]["private"], datadir)
            if filepath == None:
                print("Error, {} is not found.".format(cfg["resource"]["private"]))
                sys.exit(1)
            statinfo = os.stat(filepath)
            files["resource/private"] = statinfo.st_size
            files["round(resource/private)"] = round_up(statinfo.st_size, 32)

        if "pubkey" in cfg["resource"]:
            filepath = get_file_path(cfg["resource"]["pubkey"], keydir)
            if filepath == None:
                filepath = get_file_path(cfg["resource"]["pubkey"], datadir)
            if filepath == None:
                print("Error, {} is not found.".format(cfg["resource"]["pubkey"]))
                sys.exit(1)
            statinfo = os.stat(filepath)
            files["resource/pubkey"] = statinfo.st_size
            files["round(resource/pubkey)"] = round_up(statinfo.st_size, 32)
        if "pbp" in cfg["resource"]:
            filepath = get_file_path(cfg["resource"]["pbp"], datadir)
            if filepath == None:
                print("Error, {} is not found.".format(cfg["resource"]["pbp"]))
                sys.exit(1)
            statinfo = os.stat(filepath)
            files["resource/pbp"] = statinfo.st_size
            files["round(resource/pbp)"] = round_up(statinfo.st_size, 32)
    if "encryption" in cfg:
        if "iv" in cfg["encryption"]:
            filepath = get_file_path(cfg["encryption"]["iv"], keydir)
            if filepath == None:
                filepath = get_file_path(cfg["encryption"]["iv"], datadir)
            if filepath == None:
                print("Error, {} is not found.".format(cfg["encryption"]["iv"]))
                sys.exit(1)
            statinfo = os.stat(filepath)
            files["encryption/iv"] = statinfo.st_size
            files["round(encryption/iv)"] = round_up(statinfo.st_size, 32)
    if "loader" in cfg:
        if "file" in cfg["loader"]:
            filepath = get_file_path(cfg["loader"]["file"], datadir)
            if filepath != None:
                statinfo = os.stat(filepath)
                if statinfo.st_size > (4 * 1024 * 1024):
                    print("Loader size is too large")
                    sys.exit(1)
                files["loader/file"] = statinfo.st_size
                files["round(loader/file)"] = round_up(statinfo.st_size, 256)
            else:
                print("File {} is not exist".format(cfg["loader"]["file"]))
                sys.exit(1)
    return files

def aic_boot_calc_image_length(filesizes, sign):
    """ Calculate the boot image's total length
    """
    total_siz = filesizes["resource_start"]
    if "resource/pubkey" in filesizes:
        total_siz = total_siz + filesizes["round(resource/pubkey)"]
    if "encryption/iv" in filesizes:
        total_siz = total_siz + filesizes["round(encryption/iv)"]
    if "resource/private" in filesizes:
        total_siz = total_siz + filesizes["round(resource/private)"]
    if "resource/pbp" in filesizes:
        total_siz = total_siz + filesizes["round(resource/pbp)"]
    total_siz = round_up(total_siz, 256)
    if sign:
        # Add the length of signature
        total_siz = total_siz + 256
    else:
        # Add the length of md5
        total_siz = total_siz + 16
    return total_siz

def aic_boot_calc_image_length_for_ext(filesizes, sign):
    """ Calculate the boot image's total length
    """
    total_siz = filesizes["resource_start"]
    if "resource/pubkey" in filesizes:
        total_siz = total_siz + filesizes["round(resource/pubkey)"]
    if "resource/private" in filesizes:
        total_siz = total_siz + filesizes["round(resource/private)"]
    total_siz = round_up(total_siz, 256)
    if sign:
        # Add the length of signature
        total_siz = total_siz + 256
    else:
        # Add the length of md5
        total_siz = total_siz + 16
    return total_siz

def check_loader_run_in_dram(cfg):
    if "loader" not in cfg:
        return False
    if "run in dram" in cfg["loader"]:
        if cfg["loader"]["run in dram"].upper() == "FALSE":
            return False
    return True

def aic_boot_get_loader_bytes(cfg, filesizes):
    """ Read the loader's binaray data, and perform encryption if it is needed.
    """

    loader_size = 0
    header_size = 256
    rawbytes = bytearray(0)
    if check_loader_run_in_dram(cfg):
        # No loader in first aicimg
        # Record the information to generate header and resource bytes
        filesizes["resource_start"] = header_size + loader_size
        return rawbytes

    if "round(loader/file)" in filesizes:
        loader_size = filesizes["round(loader/file)"]
        try:
            fpath = get_file_path(cfg["loader"]["file"], cfg["datadir"])
            with open(fpath, "rb") as f:
                rawbytes = f.read(loader_size)
        except IOError:
            print("Failed to open loader file: {}".format(fpath))
            sys.exit(1)

        if len(rawbytes) == 0:
            print("Read loader data failed.")
            sys.exit(1)
        if len(rawbytes) < loader_size:
            rawbytes = rawbytes + bytearray(loader_size - len(rawbytes))

    # Record the information to generate header and resource bytes
    filesizes["resource_start"] = header_size + loader_size

    if "encryption" in cfg and loader_size > 0:
        # Only encrypt loader content, if loader not exist, don't do it
        try:
            fpath = get_file_path(cfg["encryption"]["key"], cfg["keydir"])
            if fpath == None:
                fpath = get_file_path(cfg["encryption"]["key"], cfg["datadir"])
            with open(fpath, "rb") as f:
                keydata = f.read(16)
        except IOError:
            print('Failed to open aes key file')
            sys.exit(1)
        try:
            fpath = get_file_path(cfg["encryption"]["iv"], cfg["keydir"])
            if fpath == None:
                fpath = get_file_path(cfg["encryption"]["iv"], cfg["datadir"])
            with open(fpath, "rb") as f:
                ivdata = f.read(16)
        except IOError:
            print('Failed to open iv file')
            sys.exit(1)
        cipher = AES.new(keydata, AES.MODE_CBC, ivdata)
        enc_bytes = cipher.encrypt(rawbytes)
        return enc_bytes
    else:
        return rawbytes

def aic_boot_get_loader_for_ext(cfg, filesizes):
    """ Read the loader's binaray data, and perform encryption if it is needed.
    """

    loader_size = 0
    rawbytes = bytearray(0)
    if "round(loader/file)" in filesizes:
        loader_size = filesizes["round(loader/file)"]
        try:
            fpath = get_file_path(cfg["loader"]["file"], cfg["datadir"])
            with open(fpath, "rb") as f:
                rawbytes = f.read(loader_size)
        except IOError:
            print("Failed to open loader file: {}".format(fpath))
            sys.exit(1)

        if len(rawbytes) == 0:
            print("Read loader data failed.")
            sys.exit(1)
        if len(rawbytes) < loader_size:
            rawbytes = rawbytes + bytearray(loader_size - len(rawbytes))

    header_size = 256
    # Record the information to generate header and resource bytes
    filesizes["resource_start"] = header_size + loader_size

    return rawbytes

def aic_boot_get_resource_bytes(cfg, filesizes):
    """ Pack all resource data into boot image's resource section
    """
    resbytes = bytearray(0)
    if "resource/pbp" in filesizes:
        pbp_size = filesizes["round(resource/pbp)"]
        try:
            fpath = get_file_path(cfg["resource"]["pbp"], cfg["datadir"])
            with open(fpath, "rb") as f:
                pbp_data = f.read(pbp_size)
        except IOError:
            print('Failed to open pbp file')
            sys.exit(1)
        resbytes = resbytes + pbp_data + bytearray(pbp_size - len(pbp_data))
    if "resource/private" in filesizes:
        priv_size = filesizes["round(resource/private)"]
        try:
            fpath = get_file_path(cfg["resource"]["private"], cfg["datadir"])
            with open(fpath, "rb") as f:
                privdata = f.read(priv_size)
        except IOError:
            print('Failed to open private file')
            sys.exit(1)
        resbytes = resbytes + privdata + bytearray(priv_size - len(privdata))
    if "resource/pubkey" in filesizes:
        pubkey_size = filesizes["round(resource/pubkey)"]
        try:
            fpath = get_file_path(cfg["resource"]["pubkey"], cfg["keydir"])
            if fpath == None:
                fpath = get_file_path(cfg["resource"]["pubkey"], cfg["datadir"])
            with open(fpath, "rb") as f:
                pkdata = f.read(pubkey_size)
        except IOError:
            print('Failed to open pubkey file')
            sys.exit(1)
        # Add padding to make it alignment
        resbytes = resbytes + pkdata + bytearray(pubkey_size - len(pkdata))
    if "encryption/iv" in filesizes:
        iv_size = filesizes["round(encryption/iv)"]
        try:
            fpath = get_file_path(cfg["encryption"]["iv"], cfg["keydir"])
            if fpath == None:
                fpath = get_file_path(cfg["encryption"]["iv"], cfg["datadir"])
            with open(fpath, "rb") as f:
                ivdata = f.read(iv_size)
        except IOError:
            print('Failed to open iv file')
            sys.exit(1)
        resbytes = resbytes + ivdata + bytearray(iv_size - len(ivdata))
    if len(resbytes) > 0:
        res_size = round_up(len(resbytes), 256)
        if len(resbytes) != res_size:
            resbytes = resbytes + bytearray(res_size - len(resbytes))
    return resbytes

def aic_boot_get_resource_for_ext(cfg, filesizes):
    """ Pack all resource data into boot image's resource section
    """
    resbytes = bytearray(0)
    if "resource/private" in filesizes:
        priv_size = filesizes["round(resource/private)"]
        try:
            fpath = get_file_path(cfg["resource"]["private"], cfg["datadir"])
            with open(fpath, "rb") as f:
                privdata = f.read(priv_size)
        except IOError:
            print('Failed to open private file')
            sys.exit(1)
        resbytes = resbytes + privdata + bytearray(priv_size - len(privdata))
    if "resource/pubkey" in filesizes:
        pubkey_size = filesizes["round(resource/pubkey)"]
        try:
            fpath = get_file_path(cfg["resource"]["pubkey"], cfg["keydir"])
            if fpath == None:
                fpath = get_file_path(cfg["resource"]["pubkey"], cfg["datadir"])
            with open(fpath, "rb") as f:
                pkdata = f.read(pubkey_size)
        except IOError:
            print('Failed to open pubkey file')
            sys.exit(1)
        # Add padding to make it alignment
        resbytes = resbytes + pkdata + bytearray(pubkey_size - len(pkdata))
    if len(resbytes) > 0:
        res_size = round_up(len(resbytes), 256)
        if len(resbytes) != res_size:
            resbytes = resbytes + bytearray(res_size - len(resbytes))
    return resbytes

def aic_boot_checksum(bootimg):
    length = len(bootimg)
    offset = 0
    total = 0
    while offset < length:
        val = int.from_bytes(bootimg[offset: offset + 4], byteorder='little', signed=False)
        total = total + val
        offset = offset + 4
    return (~total) & 0xFFFFFFFF

def aic_calc_checksum(start, size):
    offset = 0
    total = 0
    while offset < size:
        val = int.from_bytes(start[offset: offset + 4], byteorder='little', signed=False)
        total = total + val
        offset = offset + 4
    return (~total) & 0xFFFFFFFF

def aic_boot_add_header(h, n):
    return h + n.to_bytes(4, byteorder='little', signed=False)

def aic_boot_gen_header_bytes(cfg, filesizes):
    """ Generate header bytes
    """
    # Prepare header information
    magic = "AIC "
    checksum = 0
    header_ver = int("0x00010001", 16)
    if "head_ver" in cfg:
        header_ver = int(cfg["head_ver"], 16)

    img_len = aic_boot_calc_image_length(filesizes, "signature" in cfg)
    fw_ver = 0
    if "anti-rollback counter" in cfg:
        fw_ver = cfg["anti-rollback counter"]

    loader_length = 0
    if "loader/file" in filesizes:
        loader_length = filesizes["loader/file"]

    loader_ext_offset = 0
    if check_loader_run_in_dram(cfg):
        loader_length = 0
        loader_ext_offset = img_len
        # ensure ext loader start position is aligned to 512
        loader_ext_offset = round_up(img_len, META_ALIGNED_SIZE)

    load_address = 0
    entry_point = 0
    if "loader" in cfg:
        load_address = int(cfg["loader"]["load address"], 16)
        entry_point = int(cfg["loader"]["entry point"], 16)
    sign_algo = 0
    sign_offset = 0
    sign_length = 0
    sign_key_offset = 0
    sign_key_length = 0
    next_res_offset = filesizes["resource_start"]
    pbp_data_offset = 0
    pbp_data_length = 0
    if "resource" in cfg and "pbp" in cfg["resource"]:
        pbp_data_offset = next_res_offset
        pbp_data_length = filesizes["resource/pbp"]
        next_res_offset = pbp_data_offset + filesizes["round(resource/pbp)"]
    priv_data_offset = 0
    priv_data_length = 0
    if "resource" in cfg and "private" in cfg["resource"]:
        priv_data_offset = next_res_offset
        priv_data_length = filesizes["resource/private"]
        next_res_offset = priv_data_offset + filesizes["round(resource/private)"]
    if "signature" in cfg and cfg["signature"]["algo"] == "rsa,2048":
        sign_algo = 1
        sign_length = 256
        sign_offset = img_len - sign_length
    else:
        # Append md5 result to the end
        sign_algo = 0
        sign_length = 16
        sign_offset = img_len - sign_length

    if "resource" in cfg and "pubkey" in cfg["resource"]:
        sign_key_offset = next_res_offset
        # Set the length value equal to real size
        sign_key_length = filesizes["resource/pubkey"]
        # Calculate offset use the size after alignment
        next_res_offset = sign_key_offset + filesizes["round(resource/pubkey)"]
    enc_algo = 0
    iv_data_offset = 0
    iv_data_length = 0
    if "encryption" in cfg and cfg["encryption"]["algo"] == "aes-128-cbc":
        enc_algo = 1
        iv_data_offset = next_res_offset
        iv_data_length = 16
        next_res_offset = iv_data_offset + filesizes["round(encryption/iv)"]
    # Generate header bytes
    header_bytes = magic.encode(encoding="utf-8")
    header_bytes = aic_boot_add_header(header_bytes, checksum)
    header_bytes = aic_boot_add_header(header_bytes, header_ver)
    header_bytes = aic_boot_add_header(header_bytes, img_len)
    header_bytes = aic_boot_add_header(header_bytes, fw_ver)
    header_bytes = aic_boot_add_header(header_bytes, loader_length)
    header_bytes = aic_boot_add_header(header_bytes, load_address)
    header_bytes = aic_boot_add_header(header_bytes, entry_point)
    header_bytes = aic_boot_add_header(header_bytes, sign_algo)
    header_bytes = aic_boot_add_header(header_bytes, enc_algo)
    header_bytes = aic_boot_add_header(header_bytes, sign_offset)
    header_bytes = aic_boot_add_header(header_bytes, sign_length)
    header_bytes = aic_boot_add_header(header_bytes, sign_key_offset)
    header_bytes = aic_boot_add_header(header_bytes, sign_key_length)
    header_bytes = aic_boot_add_header(header_bytes, iv_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, iv_data_length)
    header_bytes = aic_boot_add_header(header_bytes, priv_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, priv_data_length)
    header_bytes = aic_boot_add_header(header_bytes, pbp_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, pbp_data_length)
    header_bytes = aic_boot_add_header(header_bytes, loader_ext_offset)
    header_bytes = header_bytes + bytearray(256 - len(header_bytes))
    return header_bytes

def aic_boot_gen_header_for_ext(cfg, filesizes):
    """ Generate header bytes
    """
    # Prepare header information
    magic = "AIC "
    checksum = 0
    header_ver = int("0x00010001", 16)
    if "head_ver" in cfg:
        header_ver = int(cfg["head_ver"], 16)

    img_len = aic_boot_calc_image_length_for_ext(filesizes, "signature" in cfg)
    fw_ver = 0

    loader_length = 0
    if "loader/file" in filesizes:
        loader_length = filesizes["loader/file"]

    loader_ext_offset = 0

    load_address = 0
    entry_point = 0
    if "loader" in cfg:
        if "load address ext" in cfg["loader"]:
            load_address = int(cfg["loader"]["load address ext"], 16)
        else:
            load_address = int(cfg["loader"]["load address"], 16)
        if "entry point ext" in cfg["loader"]:
            entry_point = int(cfg["loader"]["entry point ext"], 16)
        else:
            entry_point = int(cfg["loader"]["entry point"], 16)
    sign_algo = 0
    sign_offset = 0
    sign_length = 0
    sign_key_offset = 0
    sign_key_length = 0
    next_res_offset = filesizes["resource_start"]
    priv_data_offset = 0
    priv_data_length = 0
    if "resource" in cfg and "private" in cfg["resource"]:
        priv_data_offset = next_res_offset
        priv_data_length = filesizes["resource/private"]
        next_res_offset = priv_data_offset + filesizes["round(resource/private)"]
    if "signature" in cfg and cfg["signature"]["algo"] == "rsa,2048":
        sign_algo = 1
        sign_length = 256
        sign_offset = img_len - sign_length
    else:
        # Append md5 result to the end
        sign_algo = 0
        sign_length = 16
        sign_offset = img_len - sign_length

    if "resource" in cfg and "pubkey" in cfg["resource"]:
        sign_key_offset = next_res_offset
        # Set the length value equal to real size
        sign_key_length = filesizes["resource/pubkey"]
        # Calculate offset use the size after alignment
        next_res_offset = sign_key_offset + filesizes["round(resource/pubkey)"]
    enc_algo = 0
    iv_data_offset = 0
    iv_data_length = 0
    pbp_data_offset = 0
    pbp_data_length = 0
    # Generate header bytes
    header_bytes = magic.encode(encoding="utf-8")
    header_bytes = aic_boot_add_header(header_bytes, checksum)
    header_bytes = aic_boot_add_header(header_bytes, header_ver)
    header_bytes = aic_boot_add_header(header_bytes, img_len)
    header_bytes = aic_boot_add_header(header_bytes, fw_ver)
    header_bytes = aic_boot_add_header(header_bytes, loader_length)
    header_bytes = aic_boot_add_header(header_bytes, load_address)
    header_bytes = aic_boot_add_header(header_bytes, entry_point)
    header_bytes = aic_boot_add_header(header_bytes, sign_algo)
    header_bytes = aic_boot_add_header(header_bytes, enc_algo)
    header_bytes = aic_boot_add_header(header_bytes, sign_offset)
    header_bytes = aic_boot_add_header(header_bytes, sign_length)
    header_bytes = aic_boot_add_header(header_bytes, sign_key_offset)
    header_bytes = aic_boot_add_header(header_bytes, sign_key_length)
    header_bytes = aic_boot_add_header(header_bytes, iv_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, iv_data_length)
    header_bytes = aic_boot_add_header(header_bytes, priv_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, priv_data_length)
    header_bytes = aic_boot_add_header(header_bytes, pbp_data_offset)
    header_bytes = aic_boot_add_header(header_bytes, pbp_data_length)
    header_bytes = aic_boot_add_header(header_bytes, loader_ext_offset)
    header_bytes = header_bytes + bytearray(256 - len(header_bytes))
    return header_bytes

def aic_boot_gen_signature_bytes(cfg, bootimg):
    """ Generate RSASSA-PKCS1-v1.5 Signature with SHA-256
    """
    if "privkey" not in cfg["signature"]:
        print("RSA Private key is not exist.")
        sys.exit(1)
    try:
        fpath = get_file_path(cfg["signature"]["privkey"], cfg["keydir"])
        if fpath == None:
            fpath = get_file_path(cfg["signature"]["privkey"], cfg["datadir"])
        with open(fpath, 'rb') as frsa:
            rsakey = RSA.importKey(frsa.read())
    except IOError:
        print("Failed to open file: " + cfg["signature"]["privkey"])
        sys.exit(1)
    # Check if it is private key
    if rsakey.has_private() == False:
        print("Should to use RSA private key to sign")
        sys.exit(1)
    keysize = max(1, math.ceil(rsakey.n.bit_length() / 8))
    if keysize != 256:
        print("Only RSA 2048 is supported, please input RSA 2048 Private Key.")
        sys.exit(1)
    # Calculate SHA-256 hash
    sha256 = SHA256.new()
    sha256.update(bootimg)
    # Encrypt the hash, and using RSASSA-PKCS1-V1.5 Padding
    signer = PKCS1_v1_5.new(rsakey)
    sign_bytes = signer.sign(sha256)
    return sign_bytes

def aic_boot_gen_img_md5_bytes(cfg, bootimg):
    """ Calculate MD5 of image to make brom verify image faster
    """
    # Calculate MD5 hash
    md5 = MD5.new()
    md5.update(bootimg)
    md5_bytes = md5.digest()
    return md5_bytes

def aic_boot_check_params(cfg):
    if "encryption" in cfg and cfg["encryption"]["algo"] != "aes-128-cbc":
        print("Only support aes-128-cbc encryption")
        return False
    if "signature" in cfg and cfg["signature"]["algo"] != "rsa,2048":
        print("Only support rsa,2048 signature")
        return False
    # if "loader" not in cfg or "load address" not in cfg["loader"]:
    #     print("load address is not set")
    #     return False
    # if "loader" not in cfg or "entry point" not in cfg["loader"]:
    #     print("entry point is not set")
    #     return False
    return True

def aic_boot_create_image(cfg, keydir, datadir):
    """ Create AIC format Boot Image for Boot ROM
    """
    if aic_boot_check_params(cfg) == False:
        sys.exit(1)
    filesizes = aic_boot_get_resource_file_size(cfg, keydir, datadir)

    loader_bytes = aic_boot_get_loader_bytes(cfg, filesizes)
    resource_bytes = bytearray(0)
    if "resource" in cfg or "encryption" in cfg:
        resource_bytes = aic_boot_get_resource_bytes(cfg, filesizes)
    header_bytes = aic_boot_gen_header_bytes(cfg, filesizes)
    bootimg = header_bytes + loader_bytes + resource_bytes

    head_ver = int("0x00010001", 16)
    if "head_ver" in cfg:
        head_ver = int(cfg["head_ver"], 16)
    if "signature" in cfg:
        signature_bytes = aic_boot_gen_signature_bytes(cfg, bootimg)
        bootimg = bootimg + signature_bytes
        return bootimg

    # Secure boot is not enabled, always add md5 result to the end
    md5_bytes = aic_boot_gen_img_md5_bytes(cfg, bootimg[8:])
    bootimg = bootimg + md5_bytes
    # Calculate checksum.
    # When MD5 is disabled, checksum will be checked by BROM.
    cs = aic_boot_checksum(bootimg)
    cs_bytes = cs.to_bytes(4, byteorder='little', signed=False)
    bootimg = bootimg[0:4] + cs_bytes + bootimg[8:]
    # Verify the checksum value
    cs = aic_boot_checksum(bootimg)
    if cs != 0:
        print("Checksum is error: {}".format(cs))
        sys.exit(1)
    return bootimg

def aic_boot_create_ext_image(cfg, keydir, datadir):
    """ Create AIC format Boot Image for Boot ROM
    """

    filesizes = aic_boot_get_resource_file_size(cfg, keydir, datadir)
    loader_bytes = aic_boot_get_loader_for_ext(cfg, filesizes)
    resource_bytes = bytearray(0)
    if "resource" in cfg:
        resource_bytes = aic_boot_get_resource_for_ext(cfg, filesizes)
    header_bytes = aic_boot_gen_header_for_ext(cfg, filesizes)
    bootimg = header_bytes + loader_bytes + resource_bytes

    head_ver = int("0x00010001", 16)
    if "head_ver" in cfg:
        head_ver = int(cfg["head_ver"], 16)
    if "signature" in cfg:
        signature_bytes = aic_boot_gen_signature_bytes(cfg, bootimg)
        bootimg = bootimg + signature_bytes
        return bootimg

    # Secure boot is not enabled, always add md5 result to the end
    md5_bytes = aic_boot_gen_img_md5_bytes(cfg, bootimg[8:])
    bootimg = bootimg + md5_bytes
    # Calculate checksum.
    # When MD5 is disabled, checksum will be checked by BROM.
    cs = aic_boot_checksum(bootimg)
    cs_bytes = cs.to_bytes(4, byteorder='little', signed=False)
    bootimg = bootimg[0:4] + cs_bytes + bootimg[8:]
    # Verify the checksum value
    cs = aic_boot_checksum(bootimg)
    if cs != 0:
        print("Checksum is error: {}".format(cs))
        sys.exit(1)
    return bootimg

def itb_create_image(itsname, itbname, keydir, dtbname, script_dir):
    mkcmd = os.path.join(script_dir, "mkimage")
    if os.path.exists(mkcmd) == False:
        mkcmd = "mkimage"
    if sys.platform == "win32":
        mkcmd += ".exe"
    # If the key exists, generate image signature information and write it to the itb file.
    # If the key exists, write the public key to the dtb file.
    if keydir != None and dtbname != None:
        cmd = [mkcmd, "-E", "-B 0x800", "-f", itsname, "-k", keydir, "-K", dtbname, "-r", itbname]
    else:
        cmd = [mkcmd, "-E", "-B 0x800", "-f", itsname, itbname]

    ret = subprocess.run(cmd, stdout=subprocess.PIPE)
    if ret.returncode != 0:
        sys.exit(1)

def img_gen_fw_file_name(cfg):
    # Image file name format:
    # <platform>_<product>_v<version>_c<anti-rollback counter>.img
    img_file_name = cfg["image"]["info"]["platform"];
    img_file_name += "_"
    img_file_name += cfg["image"]["info"]["product"];
    img_file_name += "_v"
    img_file_name += cfg["image"]["info"]["version"];
    if "anti-rollback" in cfg["image"]["info"]:
        img_file_name += "_c"
        img_file_name += cfg["image"]["info"]["anti-rollback"];
    img_file_name += ".img"
    return img_file_name.replace(" ", "_")

def calc_crc32(fname, size):
    """Calculate crc32 for a file
    Args:
        fname: file path
    """
    hash = 0
    step = 16 * 1024
    if size > 0:
        step = size

    if os.path.exists(fname) == False:
        return 0

    with open(fname, 'rb') as fp:
        while True:
            s = fp.read(step)
            if not s:
                break
            hash = zlib.crc32(s, hash)
            if size > 0:
                # only need to calc first 'size' byte
                break
    return hash & 0xffffffff

def size_str_to_int(size_str):
    if "k" in size_str or "K" in size_str:
        numstr = re.sub(r"[^0-9]", "", size_str)
        return (int(numstr) * 1024)
    if "m" in size_str or "M" in size_str:
        numstr = re.sub(r"[^0-9]", "", size_str)
        return (int(numstr) * 1024 * 1024)
    if "g" in size_str or "G" in size_str:
        numstr = re.sub(r"[^0-9]", "", size_str)
        return (int(numstr) * 1024 * 1024 * 1024)
    if "0x" in size_str or "0X" in size_str:
        return int(size_str, 16)
    return 0

def str_to_nbytes(s, n):
    """ String to n bytes
    """
    ba = bytearray(s, encoding="utf-8")
    nzero = n - len(ba)
    if nzero > 0:
        ba.extend([0] * nzero)
    return bytes(ba)

def str_from_nbytes(s):
    """ String from n bytes
    """
    return str(s, encoding='utf-8')

def int_to_uint32_bytes(n):
    """ Int value to uint32 bytes
    """
    return n.to_bytes(4, byteorder='little', signed=False)

def int_to_uint8_bytes(n):
    """ Int value to uint8 bytes
    """
    return n.to_bytes(1, byteorder='little', signed=False)

def int_from_uint32_bytes(s):
    """ Int value from uint32 bytes
    """
    return int.from_bytes(s, byteorder='little', signed=False)

def round_up(x, y):
    return int((x + y - 1) / y) * y

def firmware_component_preproc(cfg, datadir, keydir, bindir):
    """ Perform firmware component pre-process
    Args:
        cfg: Dict from JSON
        datadir: working directory for image data
        keydir: key material directory for image data
    """

    preproc_cfg = cfg["temporary"]
    if "aicboot" in preproc_cfg:
        # Need to generate aicboot image
        imgnames = preproc_cfg["aicboot"].keys()
        for name in imgnames:
            imgcfg = preproc_cfg["aicboot"][name]
            imgcfg["keydir"] = keydir
            imgcfg["datadir"] = datadir
            outname = datadir + name
            if VERBOSE:
                print("\tCreating {} ...".format(outname))
            imgbytes = aic_boot_create_image(imgcfg, keydir, datadir)

            if check_loader_run_in_dram(imgcfg):
                extimgbytes = aic_boot_create_ext_image(imgcfg, keydir, datadir)
                padlen = round_up(len(imgbytes), META_ALIGNED_SIZE) - len(imgbytes)
                if padlen > 0:
                    imgbytes += bytearray(padlen)
                imgbytes += extimgbytes
                # For Debug
                # with open(outname + ".ext", "wb") as f:
                #     f.write(extimgbytes)

            with open(outname, "wb") as f:
                f.write(imgbytes)

if __name__ == "__main__":
    default_bin_root = os.path.dirname(sys.argv[0])
    if sys.platform.startswith("win"):
        default_bin_root = os.path.dirname(sys.argv[0]) + "/"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--datadir", type=str,
                        help="input image data directory")
    group.add_argument("-i", "--imgfile", type=str,
                        help="input unsigned image file")
    parser.add_argument("-o", "--outdir", type=str,
                        help="output image file dir")
    parser.add_argument("-c", "--config", type=str,
                        help="image configuration file name")
    parser.add_argument("-k", "--keydir", type=str,
                        help="key material directory")
    parser.add_argument("-e", "--extract", action='store_true',
                        help="extract extension file")
    parser.add_argument("-s", "--sign", action='store_true',
                        help="sign image file")
    parser.add_argument("-b", "--burner", action='store_true',
                        help="generate burner format image")
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="show detail information")
    args = parser.parse_args()
    if args.config == None:
        print('Error, option --config is required.')
        sys.exit(1)
    # If user not specified data directory, use current directory as default
    if args.datadir == None:
        args.datadir = './'
    if args.outdir == None:
        args.outdir = args.datadir
    if args.datadir.endswith('/') == False and args.datadir.endswith('\\') == False:
        args.datadir = args.datadir + '/'
    if args.outdir.endswith('/') == False and args.outdir.endswith('\\') == False:
        args.outdir = args.outdir + '/'
    if args.config == None:
        args.config = args.datadir + "image_cfg.json"
    if args.keydir == None:
        args.keydir = args.datadir
    if args.keydir.endswith('/') == False and args.keydir.endswith('\\') == False:
        args.keydir = args.keydir + '/'
    if args.burner:
        BURNER = True
    if args.verbose:
        VERBOSE = True

    cfg = parse_image_cfg(args.config)
    # Pre-process here, e.g: signature, encryption, ...
    if "temporary" in cfg:
        firmware_component_preproc(cfg, args.datadir, args.keydir, default_bin_root)
