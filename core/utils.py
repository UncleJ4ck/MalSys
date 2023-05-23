from PIL import Image
from subprocess import run
from colorama import Fore, Style
from core.validator import (calculate_md5, validate_pe_file, validate_sha1, validate_md5, validate_sha256, validate_file, validate_file_header, unzip_sample)
import os
import zipfile
import lief
import json
import requests
import pyzipper
import os

def download_sample(sha256_hash):
    if validate_sha256(sha256_hash):
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {
            "query": "get_file",
            "sha256_hash": sha256_hash
        }
        response = requests.post(url, data=data, timeout=15)
        if response.headers['Content-Type'] == 'application/zip':
            zip_path = f"{sha256_hash}.zip"
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            print(Fore.GREEN + f"[+] File downloaded at {zip_path}", Style.RESET_ALL,)
            unzip_sample(zip_path, sha256_hash)
        else:
            print("", response.json())
    else:
        print(Fore.RED + f"[!] Invalid Hash ! Enter a valid sha256 hash !", Style.RESET_ALL,)



def query_icon_dhash(exe=None, dhash_value=None, hash_size = 8):
    if exe:
        if not validate_pe_file(exe):
            print(Fore.RED + "[-] Not a valid PE binary.", Style.RESET_ALL,)
            return None
        binary = lief.parse(exe)
        bin = binary.resources_manager
        ico = bin.icons
        if not ico:
            print(Fore.RED + "[-] No icon available.", Style.RESET_ALL,)
            return None
        ico[0].save("peico.ico")
        image = Image.open("peico.ico").convert('L').resize((hash_size + 1, hash_size), Image.ANTIALIAS)
        difference = []
        for row in range(hash_size):
            for col in range(hash_size):
                pixel_left = image.getpixel((col, row))
                pixel_right = image.getpixel((col + 1, row))
                difference.append(pixel_left > pixel_right)
        decimal_value = 0
        hex_string = []
        for index, value in enumerate(difference):
            if value:
                decimal_value += 2**(index % 8)
            if (index % 8) == 7:
                hex_string.append(hex(decimal_value)[2:].rjust(2, '0'))
                decimal_value = 0
        os.remove("peico.ico")
        dhash = ''.join(hex_string)
        print(Fore.GREEN + "[+] Icon Dhash:", dhash,  Style.RESET_ALL,)
    elif dhash_value:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {
            "query": "get_dhash_icon",
            "dhash_icon": dhash_value,
            "limit": 5
        }
        response = requests.post(url, data=data)
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("query_status") == "ok":
                data = json_response.get("data")
                if data:
                    for sample in data:
                        sha256_hash = sample.get("sha256_hash")
                        sha3_384_hash = sample.get("sha3_384_hash")
                        sha1_hash = sample.get("sha1_hash")
                        md5_hash = sample.get("md5_hash")
                        first_seen = sample.get("first_seen")
                        last_seen = sample.get("last_seen")
                        file_name = sample.get("file_name")
                        file_size = sample.get("file_size")
                        file_type_mime = sample.get("file_type_mime")
                        file_type = sample.get("file_type")
                        reporter = sample.get("reporter")
                        anonymous = sample.get("anonymous")
                        signature = sample.get("signature")
                        imphash = sample.get("imphash")
                        tlsh = sample.get("tlsh")
                        dhash_icon = sample.get("dhash_icon")
                        code_sign = sample.get("code_sign")
                        ssdeep = sample.get("ssdeep")
                        tags = sample.get("tags")
                        delivery_method = sample.get("delivery_method")
                        intelligence = sample.get("intelligence")
                        print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
                        print(Fore.GREEN + "[+] SHA256 Hash:", sha256_hash, Style.RESET_ALL) if sha256_hash else print(Fore.RED + "[+] SHA256 Hash: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] SHA3-384 Hash:", sha3_384_hash, Style.RESET_ALL) if sha3_384_hash else print(Fore.RED + "[+] SHA3-384 Hash: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] SHA1 Hash:", sha1_hash, Style.RESET_ALL) if sha1_hash else print(Fore.RED + "[+] SHA1 Hash: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] MD5 Hash:", md5_hash, Style.RESET_ALL) if md5_hash else print(Fore.RED + "[+] MD5 Hash: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] First Seen:", first_seen, Style.RESET_ALL) if first_seen else print(Fore.RED + "[+] First Seen: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Last Seen:", last_seen, Style.RESET_ALL) if last_seen else print(Fore.RED + "[+] Last Seen: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] File Name:", file_name, Style.RESET_ALL) if file_name else print(Fore.RED + "[+] File Name: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] File Size:", file_size, Style.RESET_ALL) if file_size else print(Fore.RED + "[+] File Size: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] File Type MIME:", file_type_mime, Style.RESET_ALL) if file_type_mime else print(Fore.RED + "[+] File Type MIME: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] File Type:", file_type, Style.RESET_ALL) if file_type else print(Fore.RED + "[+] File Type: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Reporter:", reporter, Style.RESET_ALL) if reporter else print(Fore.RED + "[+] Reporter: Not available", Style.RESET_ALL)
                        print((Fore.GREEN + "[+] Anonymous: " + str(bool(anonymous)) + Style.RESET_ALL) if anonymous is not None else Fore.RED + "[+] Anonymous: Not available" + Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Dhash Icon:", dhash_icon, Style.RESET_ALL) if dhash_icon else print(Fore.RED + "[+] Dhash Icon: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Tags:", tags, Style.RESET_ALL) if tags else print(Fore.RED + "[+] Tags: Not available", Style.RESET_ALL)
                        if intelligence:
                            print(Fore.GREEN + "[+] Intelligence:")
                            if isinstance(intelligence, dict):
                                for key, value in intelligence.items():
                                    if value:
                                        if isinstance(value, list):
                                            print(Fore.GREEN + f"  [-] {key.capitalize()}:")
                                            for item in value:
                                                print(Fore.GREEN + f"  	- {item}")
                                        else:
                                            print(Fore.GREEN + f"  [-] {key.capitalize()}: {value}")
                                    else:
                                        print(Fore.RED + f"  [-] {key.capitalize()}: Not available", Style.RESET_ALL)
                            else:
                                print(Fore.RED + "  [-] Invalid intelligence format:", intelligence, Style.RESET_ALL)
                        else:
                            print(Fore.RED + "[+] Intelligence: Not available", Style.RESET_ALL)
                        if code_sign:
                            if isinstance(code_sign, list):
                                for item in code_sign:
                                    print(Fore.GREEN + "[+] Code Sign Details:")
                                    if isinstance(item, dict):
                                        for key, value in item.items():
                                            if key != "subject_cn":
                                                if value:
                                                    print(Fore.GREEN + f"  [-] {key.capitalize()}: {value}")
                                                else:
                                                    print(Fore.RED + f"  [-] {key.capitalize()}: Not available", Style.RESET_ALL)
                                    else:
                                        print(Fore.RED + "  [-] Invalid code sign format:", item, Style.RESET_ALL)
                            elif isinstance(code_sign, dict):
                                for key, value in code_sign.items():
                                    if key != "subject_cn":
                                        if value:
                                            print(Fore.GREEN + f"[+] {key.capitalize()}: {value}")
                                        else:
                                            print(Fore.RED + f"[+] {key.capitalize()}: Not available", Style.RESET_ALL)
                            else:
                                print(Fore.RED + "[-] Invalid code sign format:", code_sign, Style.RESET_ALL)
                        else:
                            print(Fore.RED + "[+] Code Sign: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
                else:
                    print(Fore.RED + "[!] No results found for the dhash.", Style.RESET_ALL)
            else:
                print(Fore.RED + "[!] An error occurred while querying the dhash.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] Error: Please provide either the file path or the hash.", Style.RESET_ALL,)



def scan_file(file_path=None, hash_value=None):
    if file_path:
        if not validate_file_header(file_path):
            print(Fore.RED + "[!] Error: Invalid file header.", Style.RESET_ALL,)
            return
        hash_value = calculate_md5(file_path)
    elif hash_value:
        if not (validate_md5(hash_value) or validate_sha256(hash_value) or validate_sha1(hash_value)):
            print(Fore.RED + "[!] Error: Provided hash is not a valid MD5, SHA256, or SHA1.", Style.RESET_ALL,)
            return
    else:
        print(Fore.RED + "[!] Error: Please provide either the file path or the hash.", Style.RESET_ALL,)
        return    
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": hash_value
    }
    response = requests.post(url, data=data, timeout=15)
    result = response.json()
    if result.get('query_status') == 'ok':
        data = result['data'][0]
        sha256_hash = data.get("sha256_hash")
        sha3_384_hash = data.get("sha3_384_hash")
        sha1_hash = data.get("sha1_hash")
        md5_hash = data.get("md5_hash")
        first_seen = data.get("first_seen")
        last_seen = data.get("last_seen")
        file_name = data.get("file_name")
        file_size = data.get("file_size")
        file_type_mime = data.get("file_type_mime")
        file_type = data.get("file_type")
        reporter = data.get("reporter")
        yara_rules = data.get("yara_rules") 
        anonymous = data.get("anonymous")
        signature = data.get("signature")
        country = data.get("origin_country")
        imphash = data.get("imphash")
        tlsh = data.get("tlsh")
        archive_pwd = data.get("archive_pw")
        ssdeep = data.get("ssdeep")
        tags = data.get("tags")
        code_sign = data.get("code_sign")
        delivery_method = data.get("delivery_method")
        comment = data.get("comment")
        intelligence = data.get("intelligence")
        file_info = data.get("file_information")
        vendor_intel = data.get("vendor_intel")
        print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")        
        print(Fore.GREEN + "[+] SHA256 Hash:", sha256_hash, Style.RESET_ALL) if sha256_hash else print(Fore.RED + "[+] SHA256 Hash: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] SHA3-384 Hash:", sha3_384_hash, Style.RESET_ALL) if sha3_384_hash else print(Fore.RED + "[+] SHA3-384 Hash: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] SHA1 Hash:", sha1_hash, Style.RESET_ALL) if sha1_hash else print(Fore.RED + "[+] SHA1 Hash: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] MD5 Hash:", md5_hash, Style.RESET_ALL) if md5_hash else print(Fore.RED + "[+] MD5 Hash: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] First Seen:", first_seen, Style.RESET_ALL) if first_seen else print(Fore.RED + "[+] First Seen: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] Last Seen:", last_seen, Style.RESET_ALL) if last_seen else print(Fore.RED + "[+] Last Seen: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] File Name:", file_name, Style.RESET_ALL) if file_name else print(Fore.RED + "[+] File Name: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] File Size:", file_size, Style.RESET_ALL) if file_size else print(Fore.RED + "[+] File Size: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] File Type MIME:", file_type_mime, Style.RESET_ALL) if file_type_mime else print(Fore.RED + "[+] File Type MIME: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] File Type:", file_type, Style.RESET_ALL) if file_type else print(Fore.RED + "[+] File Type: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] Country: ", country, Style.RESET_ALL) if country else print(Fore.RED + "[+] Country: Not available" + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Reporter:", reporter, Style.RESET_ALL) if reporter else print(Fore.RED + "[+] Reporter: Not available", Style.RESET_ALL)
        print((Fore.GREEN + "[+] Anonymous: " + str(bool(anonymous)) + Style.RESET_ALL) if anonymous is not None else Fore.RED + "[+] Anonymous: Not available" + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Archive Password:", archive_pwd, Style.RESET_ALL) if archive_pwd else print(Fore.RED + "[+] Archive Password: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
        print(Fore.GREEN + "[+] Tags:", tags, Style.RESET_ALL) if tags else print(Fore.RED + "[+] Tags: Not available", Style.RESET_ALL)   
        if delivery_method:
            if isinstance(delivery_method, str):
                print(Fore.GREEN + "[+] Delivery Method:")
                print(Fore.GREEN + "  - Method:", delivery_method)
            else:
                print(Fore.GREEN + "[+] Delivery Method:")
                for method in delivery_method:
                    email_attachment = method.get("email_attachment")
                    email_link = method.get("email_link")
                    download = method.get("web_download")
                    drive = method.get("web_drive-by")
                    multiple = method.get("multiple")
                    other = method.get("other")
                    print(Fore.GREEN + "  - Email Attachment:", email_attachment) if email_attachment else print(Fore.RED + "  - Email Attachment: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "    Email Link:", email_link) if email_link else print(Fore.RED + "    Email Link: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "    Web Download:", download) if download else print(Fore.RED + "    Web Download: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "    Web Drive:", drive) if drive else print(Fore.RED + "    Web Drive: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "    Multiple:", multiple) if multiple else print(Fore.RED + "    Multiple: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "    Other:", other) if other else print(Fore.RED + "    Other: Not available", Style.RESET_ALL)
                    print(Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] Delivery Method: Not available", Style.RESET_ALL)
        if yara_rules:
            print(Fore.GREEN + "[+] Yara Rules:")
            for rule in yara_rules:
                rule_name = rule.get("rule_name")
                author = rule.get("author")
                description = rule.get("description")
                reference = rule.get("reference")
                print(Fore.GREEN + "  - Rule Name:", rule_name) if rule_name else print(Fore.RED + "  - Rule Name: Not available", Style.RESET_ALL)
                print(Fore.GREEN + "    Author:", author) if author else print(Fore.RED + "    Author: Not available", Style.RESET_ALL)
                print(Fore.GREEN + "    Description:", description) if description else print(Fore.RED + "    Description: Not available", Style.RESET_ALL)
                print(Fore.GREEN + "    Reference:", reference) if reference else print(Fore.RED + "    Reference: Not available", Style.RESET_ALL)
                print(Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] Yara Rules: Not available", Style.RESET_ALL)
        if comment:
            print(Fore.GREEN + "[+] Comment:")
            if isinstance(comment, str):
                print(Fore.GREEN + "  -", comment)
            elif isinstance(comment, list):
                for entry in comment:
                    if isinstance(entry, dict):
                        comment_id = entry.get("id")
                        date_added = entry.get("date_added")
                        twitter_handle = entry.get("twitter_handle")
                        display_name = entry.get("display_name")
                        comment_text = entry.get("comment")
                        print(Fore.GREEN + "  - Comment ID:", comment_id) if comment_id else print(Fore.RED + "  - Comment ID: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "    Date Added:", date_added) if date_added else print(Fore.RED + "    Date Added: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "    Twitter Handle:", twitter_handle) if twitter_handle else print(Fore.RED + "    Twitter Handle: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "    Display Name:", display_name) if display_name else print(Fore.RED + "    Display Name: Not available", Style.RESET_ALL)
                        print(Fore.GREEN + "    Comment:", comment_text) if comment_text else print(Fore.RED + "    Comment: Not available", Style.RESET_ALL)
                    else:
                        print(Fore.RED + "  [-] Invalid comment entry:", entry, Style.RESET_ALL)
                    print(Style.RESET_ALL)
            else:
                print(Fore.RED + "  [-] Invalid comment format:", comment, Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] Comment: Not available", Style.RESET_ALL)
        if intelligence:
            print(Fore.GREEN + "[+] Intelligence:")
            if isinstance(intelligence, dict):
                for key, value in intelligence.items():
                    if value:
                        if isinstance(value, list):
                            print(Fore.GREEN + f"  [-] {key.capitalize()}:")
                            for item in value:
                                print(Fore.GREEN + f"  	- {item}")
                        else:
                            print(Fore.GREEN + f"  [-] {key.capitalize()}: {value}")
                    else:
                        print(Fore.RED + f"  [-] {key.capitalize()}: Not available", Style.RESET_ALL)
            else:
                print(Fore.RED + "  [-] Invalid intelligence format:", intelligence, Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] Intelligence: Not available", Style.RESET_ALL)
        if file_info:
            print(Fore.GREEN + "[+] File Information:")
            for entry in file_info:
                for key, value in entry.items():
                    print(Fore.GREEN + "  [-]", key + ":", value) if value else print(Fore.RED + "  [-]", key + ": Not available", Style.RESET_ALL)
            print(Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] File Information: Not available", Style.RESET_ALL)
        if vendor_intel:
            print(Fore.GREEN + "[+] Vendor Intel:")
            if isinstance(vendor_intel, dict):
                for vendor, intel in vendor_intel.items():
                    print(Fore.GREEN + "  - Vendor:", vendor)
                    if isinstance(intel, dict):
                        for key, value in intel.items():
                            if isinstance(value, list):
                                print(Fore.GREEN + "    [+]", key.capitalize() + ":")
                                for entry in value:
                                    if isinstance(entry, dict):
                                        for k, v in entry.items():
                                            print(Fore.GREEN + "      [+]", k.capitalize() + ":", v) if v else print(Fore.RED + "      [+]", k.capitalize() + ": Not available", Style.RESET_ALL)
                                    else:
                                        print(Fore.RED + "      [-] Invalid entry:", entry, Style.RESET_ALL)
                            elif isinstance(value, dict):
                                for k, v in value.items():
                                    print(Fore.GREEN + "    [+]", k.capitalize() + ":", v) if v else print(Fore.RED + "    [+]", k.capitalize() + ": Not available", Style.RESET_ALL)
                            else:
                                print(Fore.GREEN + "    [+]", key.capitalize() + ":", value) if value else print(Fore.RED + "    [+]", key.capitalize() + ": Not available", Style.RESET_ALL)
                    elif isinstance(intel, list):
                        for item in intel:
                            if isinstance(item, dict):
                                for key, value in item.items():
                                    if isinstance(value, list):
                                        print(Fore.GREEN + "    [+]", key.capitalize() + ":")
                                        for entry in value:
                                            if isinstance(entry, dict):
                                                for k, v in entry.items():
                                                    print(Fore.GREEN + "      [+]", k.capitalize() + ":", v) if v else print(Fore.RED + "      [+]", k.capitalize() + ": Not available", Style.RESET_ALL)
                                            else:
                                                print(Fore.RED + "      [-] Invalid entry:", entry, Style.RESET_ALL)
                                    else:
                                        print(Fore.GREEN + "    [+]", key.capitalize() + ":", value) if value else print(Fore.RED + "    [+]", key.capitalize() + ": Not available", Style.RESET_ALL)
                            else:
                                print(Fore.RED + "    [-] Invalid intel format:", item, Style.RESET_ALL)
                    else:
                        print(Fore.RED + "    [-] Invalid intel format:", intel, Style.RESET_ALL)
                    print(Style.RESET_ALL)
            else:
                print(Fore.RED + "  [-] Invalid vendor intel format:", vendor_intel, Style.RESET_ALL)
        else:
            print(Fore.RED + "[+] Vendor Intel: Not available", Style.RESET_ALL)
            if code_sign:
                if isinstance(code_sign, list):
                    for item in code_sign:
                        print(Fore.GREEN + "[+] Code Sign Details:")
                        if isinstance(item, dict):
                            for key, value in item.items():
                                if key != "subject_cn":
                                    if value:
                                        print(Fore.GREEN + f"  [-] {key.capitalize()}: {value}")
                                    else:
                                        print(Fore.RED + f"  [-] {key.capitalize()}: Not available", Style.RESET_ALL)
                        else:
                            print(Fore.RED + "  [-] Invalid code sign format:", item, Style.RESET_ALL)
                elif isinstance(code_sign, dict):
                    for key, value in code_sign.items():
                        if key != "subject_cn":
                            if value:
                                print(Fore.GREEN + f"[+] {key.capitalize()}: {value}")
                            else:
                                print(Fore.RED + f"[+] {key.capitalize()}: Not available", Style.RESET_ALL)
                else:
                    print(Fore.RED + "[-] Invalid code sign format:", code_sign, Style.RESET_ALL)
            else:
                print(Fore.RED + "[+] Code Sign: Not available", Style.RESET_ALL)
            print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)



def update_entry(sha256_hash, key, value, api_key):
    if validate_sha256(sha256_hash):
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"API-KEY": api_key}
        data = {
            "query": "update",
            "sha256_hash": sha256_hash,
            "key": key,
            "value": value
        }
        response = requests.post(url, data=data, headers=headers, timeout=15)
        response_json = response.json()
        query_status = response_json.get('query_status', None)
        status_comment = {
            "http_post_expected": "The API expected a HTTP POST request",
            "no_api_key": "You did not provide an API key. You can obtain one here",
            "user_blacklisted": "Your API key is blacklisted. Please contact us through the Spamhaus Technology contact form: https://www.spamhaus.com/#contact-form",
            "hash_not_found": "The file (hash) you wanted to update is unknown to MalwareBazaar",
            "illegal_hash": "The hash you provided is not a valid SHA256 hash",
            "permission_denied": "The database entry you have tried to update is not owned by your account",
            "unknown_key": "The key (add parameter) you wanted to update is not known",
            "exists": "The key -> value already exists",
            "updated": "Entry has been updated"
        }
        if query_status in status_comment:
            print(f"[+] query_status: {query_status}, Comment: {status_comment[query_status]}")
        else:
            print("Unknown status received: ", query_status)