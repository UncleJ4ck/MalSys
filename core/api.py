from core.validator import validate_file
from colorama import Fore, Style
import requests
import json

def query_yara_rule(yara_rule):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_yarainfo",
        "yara_rule": yara_rule,
        "limit": 50
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
                        ssdeep = sample.get("ssdeep")
                        tags = sample.get("tags")
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
                    print(Fore.RED + "[!] No results found for the Yara Rule.", Style.RESET_ALL)
            else:
                print(Fore.RED + "[!] An error occurred while querying the Yara Rule.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_telfhash(telfhash, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_telfhash",
        "telfhash": telfhash,
        "limit": limit
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
                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for the telfhash.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the telfhash.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)

def query_imphash(imphash, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_imphash",
        "imphash": imphash,
        "limit": limit
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
                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for the filetype.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the filetype.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)

def query_tag(tag, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_taginfo",
        "tag": tag,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                print(Fore.RED + "[!] No results found for the tag.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the tag.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)

def query_signature(signature, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_siginfo",
        "signature": signature,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    imphash = sample.get("imphash")
                    tlsh = sample.get("tlsh")
                    dhash_icon = sample.get("dhash_icon")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                    print((Fore.GREEN + "[+] Dhash Icon: " + str(dhash_icon) + Style.RESET_ALL) if dhash_icon else Fore.RED + "[+] Dhash Icon: Not available" + Style.RESET_ALL) 
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
                print(Fore.RED + "[!] No results found for the signature.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the signature.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_filetype(file_type, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_file_type",
        "file_type": file_type,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tlsh = sample.get("tlsh")
                    dhash_icon = sample.get("dhash_icon")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                    print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
                    print((Fore.GREEN + "[+] Dhash Icon: " + str(dhash_icon) + Style.RESET_ALL) if dhash_icon else Fore.RED + "[+] Dhash Icon: Not available" + Style.RESET_ALL) 
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
                print(Fore.RED + "[!] No results found for the filetype.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the filetype.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_clamav_signature(clamav_signature, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_clamavinfo",
        "clamav": clamav_signature,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    code_sign = sample.get("code_sign")
                    tlsh = sample.get("tlsh")
                    dhash_icon = sample.get("dhash_icon")
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
                    print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
                    print((Fore.GREEN + "[+] Dhash Icon: " + str(dhash_icon) + Style.RESET_ALL) if dhash_icon else Fore.RED + "[+] Dhash Icon: Not available" + Style.RESET_ALL) 
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

                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for the ClamAV Signature.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the ClamAV Signature.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_tlsh(tlsh_hash, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_tlsh",
        "tlsh": tlsh_hash,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tlsh = sample.get("tlsh")
                    dhash_icon = sample.get("dhash_icon")
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
                    print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
                    print((Fore.GREEN + "[+] Dhash Icon: " + str(dhash_icon) + Style.RESET_ALL) if dhash_icon else Fore.RED + "[+] Dhash Icon: Not available" + Style.RESET_ALL) 
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
                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for TLSH hash.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying TLSH hash.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_gimphash(hash, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_gimphash",
        "gimphash": hash,
        "limit": limit
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
                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for the gimphash.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the gimphash.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_issuer_cn(issuer_cn, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_issuerinfo",
        "issuer_cn": issuer_cn,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                print(Fore.RED + "[!] No results found for the Code Signing Certificates.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the Code Signing Certificates.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_subject_cn(subject_cn, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_subjectinfo",
        "subject_cn": subject_cn,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                print(Fore.RED + "[!] No results found for the Code Signing Certificates.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the Code Signing Certificates.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_serial_number(serial_number, limit=100):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_certificate",
        "serial_number": serial_number,
        "limit": limit
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
                    ssdeep = sample.get("ssdeep")
                    tags = sample.get("tags")
                    code_sign = sample.get("code_sign")
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
                print(Fore.RED + "[!] No results found for the Code Signing Certificates.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the Code Signing Certificates.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)

def query_recent_samples(selector):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_recent",
        "selector": selector
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
                    ssdeep = sample.get("ssdeep")
                    code_sign = sample.get("code_sign")
                    tlsh = sample.get("tlsh")
                    dhash_icon = sample.get("dhash_icon")
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
                    print(Fore.GREEN + "[+] SSDeep:", ssdeep, Style.RESET_ALL) if ssdeep else print(Fore.RED + "[+] SSDeep: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] Signature:", signature, Style.RESET_ALL) if signature else print(Fore.RED + "[+] Signature: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] ImpHash:", imphash, Style.RESET_ALL) if imphash else print(Fore.RED + "[+] ImpHash: Not available", Style.RESET_ALL)
                    print(Fore.GREEN + "[+] TLSH:", tlsh, Style.RESET_ALL) if tlsh else print(Fore.RED + "[+] TLSH: Not available", Style.RESET_ALL)
                    print((Fore.GREEN + "[+] Dhash Icon: " + str(dhash_icon) + Style.RESET_ALL) if dhash_icon else Fore.RED + "[+] Dhash Icon: Not available" + Style.RESET_ALL) 
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

                    print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
            else:
                print(Fore.RED + "[!] No results found for the ClamAV Signature.", Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] An error occurred while querying the ClamAV Signature.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)


def query_cscb():
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_cscb"
    }
    response = requests.post(url, data=data, timeout=15)
    if response.status_code == 200:
        response_json = response.json()
        if response_json.get("query_status") == "ok":
            cscb_entries = response_json.get("data")
            for entry in cscb_entries:
                print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
                time_stamp = entry.get("time_stamp")
                print(Fore.GREEN + "[+] Time Stamp:", time_stamp, Style.RESET_ALL) if time_stamp else print(Fore.RED + "[+] Time Stamp: Not available", Style.RESET_ALL)
                serial_number = entry.get("serial_number")
                print(Fore.GREEN + "[+] Serial Number:", serial_number, Style.RESET_ALL) if serial_number else print(Fore.RED + "[+] Serial Number: Not available", Style.RESET_ALL)
                thumbprint = entry.get("thumbprint")
                print(Fore.GREEN + "[+] Thumbprint:", thumbprint, Style.RESET_ALL) if thumbprint else print(Fore.RED + "[+] Thumbprint: Not available", Style.RESET_ALL)
                thumbprint_algorithm = entry.get("thumbprint_algorithm")
                print(Fore.GREEN + "[+] Thumbprint Algorithm:", thumbprint_algorithm, Style.RESET_ALL) if thumbprint_algorithm else print(Fore.RED + "[+] Thumbprint Algorithm: Not available", Style.RESET_ALL)
                subject_cn = entry.get("subject_cn")
                print(Fore.GREEN + "[+] Subject CN:", subject_cn, Style.RESET_ALL) if subject_cn else print(Fore.RED + "[+] Subject CN: Not available", Style.RESET_ALL)
                issuer_cn = entry.get("issuer_cn")
                print(Fore.GREEN + "[+] Issuer CN:", issuer_cn, Style.RESET_ALL) if issuer_cn else print(Fore.RED + "[+] Issuer CN: Not available", Style.RESET_ALL)
                valid_from = entry.get("valid_from")
                print(Fore.GREEN + "[+] Valid From:", valid_from, Style.RESET_ALL) if valid_from else print(Fore.RED + "[+] Valid From: Not available", Style.RESET_ALL)
                valid_to = entry.get("valid_to")
                print(Fore.GREEN + "[+] Valid To:", valid_to, Style.RESET_ALL) if valid_to else print(Fore.RED + "[+] Valid To: Not available", Style.RESET_ALL)
                cscb_listed = entry.get("cscb_listed")
                print((Fore.GREEN + "[+] CSCB Listed: " + str(bool(cscb_listed)) + Style.RESET_ALL) if cscb_listed is not None else Fore.RED + "[+] CSCB Listed: Not available" + Style.RESET_ALL)
                cscb_reason = entry.get("cscb_reason")
                print(Fore.GREEN + "[+] CSCB Reason:", cscb_reason, Style.RESET_ALL) if cscb_reason else print(Fore.RED + "[+] CSCB Reason: Not available", Style.RESET_ALL)
                print(Fore.GREEN + "------------------------------------------------------------------------------------------------------------------------------------------------------------------", Style.RESET_ALL, end="\n\n")
        else:
            print(Fore.RED + "[!] An error occurred while querying the CSCB.", Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] An error occurred while making the request.", Style.RESET_ALL)
