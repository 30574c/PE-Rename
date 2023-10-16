import pefile
import os
import datetime
import hashlib
import argparse
import gc


def check_directory_existence(users_provided_directory):
    try:
        if os.path.isdir(users_provided_directory):
            return True
        else:
            exit(1)
    except Exception as error:
        print(f'check_directory_existence Error ... {error}')
        exit(1)


def verify_files_in_directory(directory_path):
    # removes any paths that are not files
    directory_files = os.listdir(directory_path)
    files = []
    for file in directory_files:
        full_path = os.path.join(directoryPath, file)
        try:
            if os.path.isfile(full_path):
                files.append(full_path)
        except Exception as error:
            print(f'verify_files_in_directory Error ... {error}')
    return files


def verify_files_are_pe_files(list_of_files):
    files = []
    for file in list_of_files:
        try:
            if pefile.PE(file):
                files.append(file)
        except pefile.PEFormatError as error:
            print(f'File ({file}) is not PE file SKIPPING ... {error}')
            continue
        except Exception as error:
            print(f'verify_files_are_pe_files Error ... {error}')
    return files


def verification_steps(directory_path):
    check_directory_existence(directory_path)
    list_of_verified_files = verify_files_in_directory(directory_path)
    list_of_verified_pe_files = verify_files_are_pe_files(list_of_verified_files)
    return list_of_verified_pe_files


def rename_files_by_compilation_times(list_of_files, directory_path):
    for file in list_of_files:
        try:
            pe_binary = pefile.PE(file)
            epoch_time = pe_binary.FILE_HEADER.TimeDateStamp
            pe_binary.close()
            time = datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H_%M_%S')
            gc.collect()
            new_filename_full_path = os.path.join(directory_path, time)
            os.rename(file, new_filename_full_path)
        except Exception as error:
            print(f'rename_files_by_compilation_times Error ... {error}')


def rename_files_by_md5_digest(list_of_files, directory_path):
    for file in list_of_files:
        try:
            hash_md5 = hashlib.md5()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            gc.collect()
            new_filename_full_path = os.path.join(directory_path, hash_md5.hexdigest())
            os.rename(file, new_filename_full_path)
        except Exception as error:
            print(f'rename_files_by_md5_digest Error ... {error}')


def rename_files_by_sha1_digest(list_of_files, directory_path):
    for file in list_of_files:
        try:
            hash_sha1 = hashlib.sha1()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha1.update(chunk)
            gc.collect()
            new_filename_full_path = os.path.join(directory_path, hash_sha1.hexdigest())
            os.rename(file, new_filename_full_path)
        except Exception as error:
            print(f'rename_files_by_sha1_digest Error ... {error}')


def rename_files_by_sha256_digest(list_of_files, directory_path):
    for file in list_of_files:
        try:
            hash_sha256 = hashlib.sha256()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            gc.collect()
            new_filename_full_path = os.path.join(directory_path, hash_sha256.hexdigest())
            os.rename(file, new_filename_full_path)
        except Exception as error:
            print(f'rename_files_by_sha256_digest Error ... {error}')


# ARGPARSE
parser = argparse.ArgumentParser(description='PE-Rename - Rename all PE files in a directory')
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')
required.add_argument('-i', '--input', type=str, help='full directory path')
optional.add_argument('-m', '--modify', type=str,
                      help='modification types (compilation, md5, sha1, sha256) - DEFAULT: md5', default='md5')
parseArgs = parser.parse_args()

if parseArgs.input:
    directoryPath = ''
    if parseArgs.input:
        directoryPath = parseArgs.input
    else:
        print('No directory path provided.')
        exit(1)

    listOfFiles = verification_steps(directoryPath)

    if parseArgs.modify == 'compilation':
        rename_files_by_compilation_times(listOfFiles, directoryPath)
    elif parseArgs.modify == 'md5':
        rename_files_by_md5_digest(listOfFiles, directoryPath)
    elif parseArgs.modify == 'sha1':
        rename_files_by_sha1_digest(listOfFiles, directoryPath)
    elif parseArgs.modify == 'sha256':
        rename_files_by_sha256_digest(listOfFiles, directoryPath)
    else:
        print('Incorrect modify selection.')
        exit(1)
