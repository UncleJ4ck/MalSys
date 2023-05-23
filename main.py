from core.utils import (download_sample, scan_file, query_icon_dhash)
from core.api import (query_clamav_signature, query_cscb, query_filetype,
                 query_imphash, query_issuer_cn, query_recent_samples,
                 query_serial_number, query_signature, query_subject_cn, 
                 query_tag, query_telfhash, query_tlsh, query_yara_rule,
                 query_gimphash)
from pyfiglet import Figlet
from colorama import Fore, Style
from termcolor import cprint
import argparse


def print_banner():
    fig = Figlet(font='slant')
    cprint(fig.renderText('MalSys'), 'green')


def parse_args():
    print_banner()
    parser = argparse.ArgumentParser(
        description=f'{Fore.GREEN}API Query tool for various operations{Style.RESET_ALL}',
        epilog=f'{Fore.GREEN}For more information about each operation, type "python3 main.py <operation> -h"{Style.RESET_ALL}'
    )
    subparsers = parser.add_subparsers(dest='operation', title='Available operations')
    download_parser = subparsers.add_parser(
        'download_sample',
        help='Downloads a malware sample from MalwareBazaar',
        description=f'{Fore.GREEN}Downloads a malware sample from MalwareBazaar using a specified SHA256 hash{Style.RESET_ALL}'
    )
    download_parser.add_argument('--hash', required=True, help='SHA256 hash of the malware sample')
    query_yara_parser = subparsers.add_parser(
        'query_yara_rule',
        help='Queries a specific YARA rule',
        description=f'{Fore.GREEN}Queries a specific YARA rule using a given rule{Style.RESET_ALL}'
    )
    query_yara_parser.add_argument('--rule', required=True, help='The YARA rule to query')
    query_telfhash_parser = subparsers.add_parser(
        'query_telfhash',
        help='Queries a specific telfhash',
        description=f'{Fore.GREEN}Queries a specific telfhash using a given hash{Style.RESET_ALL}'
    )
    query_telfhash_parser.add_argument('--hash', required=True, help='The telfhash to query')
    query_dhash_parser = subparsers.add_parser(
        'query_icon_dhash',
        help='Queries an icon dhash',
        description=f'{Fore.GREEN}Queries an icon dhash using a specified file or hash{Style.RESET_ALL}'
    )
    query_dhash_parser.add_argument('--file', help='Path to the PE file')
    query_dhash_parser.add_argument('--hash', help='Hash to scan')
    scan_file_parser = subparsers.add_parser(
        'scan_file',
        help='Scans a file',
        description=f'{Fore.GREEN}[!] Scans a file using a specified file path or hash{Style.RESET_ALL}'
    )
    scan_file_parser.add_argument('--file', help='Path to the file to scan')
    scan_file_parser.add_argument('--hash', help='Hash to scan')
    query_imphash_parser = subparsers.add_parser(
        'query_imphash',
        help='Queries an imphash',
        description=f'{Fore.GREEN}Queries an imphash using a given hash{Style.RESET_ALL}'
    )
    query_imphash_parser.add_argument('--hash', required=True, help='The imphash to query')
    query_gimphash_parser = subparsers.add_parser(
        'query_gimphash',
        help='Queries a gimphash',
        description=f'{Fore.GREEN}Queries a gimphash using a given hash{Style.RESET_ALL}'
    )
    query_gimphash_parser.add_argument('--hash', required=True, help='The gimphash to query')
    query_tag_parser = subparsers.add_parser(
        'query_tag',
        help='Queries a tag',
        description=f'{Fore.GREEN}Queries a tag using a given tag{Style.RESET_ALL}'
    )
    query_tag_parser.add_argument('--tag', required=True, help='The tag to query')
    query_signature_parser = subparsers.add_parser(
        'query_signature',
        help='Queries a signature',
        description=f'{Fore.GREEN}Queries a signature using a given signature{Style.RESET_ALL}'
    )
    query_signature_parser.add_argument('--signature', required=True, help='The signature to query')
    query_file_type_parser = subparsers.add_parser(
        'query_filetype',
        help='Queries a file type',
        description=f'{Fore.GREEN}Queries a file type using a given file{Style.RESET_ALL}'
    )
    query_file_type_parser.add_argument('--file', required=True, help='The file type to query')
    query_clamav_signature_parser = subparsers.add_parser(
        'query_clamav_signature',
        help='Queries a ClamAV signature',
        description=f'{Fore.GREEN}Queries a ClamAV signature using a given signature{Style.RESET_ALL}'
    )
    query_clamav_signature_parser.add_argument('--signature', required=True, help='The ClamAV signature to query')
    update_entry_parser = subparsers.add_parser(
        'update_entry',
        help='Updates an entry',
        description=f'{Fore.GREEN}Updates an entry in the database with the specified SHA256 hash{Style.RESET_ALL}'
    )
    update_entry_parser.add_argument('--hash', required=True, help='SHA256 hash of the entry to update')
    update_entry_parser.add_argument('--key', required=True, help='Key or field to update')
    update_entry_parser.add_argument('--value', required=True, help='New value for the specified key or field')
    update_entry_parser.add_argument('--api_key', required=True, help='Your API key to authenticate the update operation')

    return parser.parse_args(), parser


if __name__ == "__main__":
    args, parser = parse_args()
    if args.operation == "download_sample":
        download_sample(args.hash)
    elif args.operation == "query_yara_rule":
        query_yara_rule(args.rule)
    elif args.operation == "query_telfhash":
        query_telfhash(args.hash)
    elif args.operation == "query_gimphash":
        query_gimphash(args.hash)
    elif args.operation == "query_icon_dhash":
        query_icon_dhash(exe=args.file, dhash_value=args.hash)
    elif args.operation == "scan_file":
        scan_file(file_path=args.file, hash_value=args.hash)
    elif args.operation == "query_imphash":
        query_imphash(args.hash)
    elif args.operation == "query_tag":
        query_tag(args.tag)
    elif args.operation == "query_signature":
        query_signature(args.signature)
    elif args.operation == "query_filetype":
        query_filetype(args.file)
    elif args.operation == "query_clamav_signature":
        query_clamav_signature(args.signature)
    elif args.operation == "query_tlsh":
        query_tlsh(args.hash)
    elif args.operation == "query_issuer_cn":
        query_issuer_cn(args.certificate)
    elif args.operation == "query_subject_cn":
        query_subject_cn(args.certificate)
    elif args.operation == "query_serial_number":
        query_serial_number(args.number)
    elif args.operation == "update_entry":
        update_entry(args.hash, args.key, args.value, args.api_key)
    elif args.operation == "query_recent_samples":
        query_recent_samples(args.selector)
    elif args.operation == "query_cscb":
        query_cscb()
    else:
        parser.print_help()
