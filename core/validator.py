from colorama import Fore, Style
import os
import re
import hashlib
import pyzipper


def validate_sha256(hash_value):
    if not isinstance(hash_value, str):
        return False
    if len(hash_value) != 64:
        return False
    if not re.fullmatch(r'[A-Fa-f0-9]{64}', hash_value):
        return False
    return True

def validate_md5(hash_value):
    if not isinstance(hash_value, str):
        return False
    if len(hash_value) != 32:
        return False
    if not re.fullmatch(r'[A-Fa-f0-9]{32}', hash_value):
        return False
    return True

def validate_sha1(hash_value):
    if not isinstance(hash_value, str):
        return False
    if len(hash_value) != 40:
        return False
    if not re.fullmatch(r'[A-Fa-f0-9]{40}', hash_value):
        return False
    return True


def validate_file(file_path):
    if not os.path.isfile(file_path):
        print(Fore.RED + "[!] Invalid file path.", Style.RESET_ALL)
        return False
    return True

def validate_file_header(file_path):
    with open(file_path, "rb") as f:
        header = f.read(4)
        if header[:2] == b"MZ":
            print(Fore.GREEN + "[+] File is a valid PE binary.", Style.RESET_ALL)
            return True
        elif header[:4] == b"\x7fELF":
            print(Fore.GREEN + "[+] File is a valid ELF binary.", Style.RESET_ALL)
            return True
        else:
            print(Fore.RED + "[!] File is neither a valid PE nor ELF binary.", Style.RESET_ALL)
            return False 

def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def unzip_sample(zip_path, sha256_hash):
    password = "infected"
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.extractall(path=f"{sha256_hash}_sample", pwd=password.encode('utf-8'))
        print(Fore.GREEN + "[+] Sample unzipped successfully.", Style.RESET_ALL)
        try:
            os.remove(zip_path)
            print(Fore.GREEN + f"[+] Zip file '{zip_path}' deleted successfully.", Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] An error occurred while deleting the zip file: {str(e)}", Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + "[!] An error occurred while unzipping the sample:", str(e), Style.RESET_ALL)


def validate_pe_file(file_path):
    with open(file_path, "rb") as f:
        header = f.read(4)
        if header[:2] == b"MZ":
            print(Fore.GREEN + "[+] File is a valid PE binary.", Style.RESET_ALL)
            return True
        return False