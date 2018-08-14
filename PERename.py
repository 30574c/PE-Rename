import pefile, os, datetime, hashlib, argparse

def checkDirectoryExistence(userProvidedDirectory):
    try:
        if(os.path.isdir(userProvidedDirectory)):
            return True
        else:
            exit(1)
    except Exception as error:
        print('checkDirectoryExistence Error ... %s' % (error))
        exit(1)

def verifyFilesInDirectory(directoryPath):

    # removes any paths that are not files
    directoryFiles = os.listdir(directoryPath)
    files = []
    for file in directoryFiles:
        fullPath = os.path.join(directoryPath, file)
        try:
            if(os.path.isfile(fullPath)):
                files.append(fullPath)
        except Exception as error:
            print('verifyFilesInDirectory Error ... %s' % (error))
    return files

def verifyFilesArePEFiles(listOfFiles):

    files = []
    for file in listOfFiles:
        try:
            if(pefile.PE(file)):
                files.append(file)
        except pefile.PEFormatError as error:
            print('File (%s) is not PE file SKIPPING ... %s' % (file, error))
            continue
        except Exception as error:
            print('verifyFilesArePEFiles Error ... %s' % (error))
    return files

def verificationSteps(directoryPath):
    checkDirectoryExistence(directoryPath)
    listOfVerifiedFiles = verifyFilesInDirectory(directoryPath)
    listOfVerifiedPEFiles = verifyFilesArePEFiles(listOfVerifiedFiles)
    return listOfVerifiedPEFiles

def renameFilesByCompilationTimes(listOfFiles, directoryPath):

    for file in listOfFiles:
        try:
            peBinary = pefile.PE(file)
            epochTime = peBinary.FILE_HEADER.TimeDateStamp
            time = datetime.datetime.fromtimestamp(epochTime).strftime('%Y-%m-%d %H_%M_%S')
            newFilenameFullPath = os.path.join(directoryPath, time)
            os.rename(file, newFilenameFullPath)
        except Exception as error:
            print('renameFilesToCompilationTimes Error ... %s' % (error))

def renameFilesByMD5Digest(listOfFiles, directoryPath):

    for file in listOfFiles:
        try:
            hash_md5 = hashlib.md5()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            newFilenameFullPath = os.path.join(directoryPath, hash_md5.hexdigest())
            os.rename(file, newFilenameFullPath)
        except Exception as error:
            print('renameFilesByMD5Digest Error ... %s' % (error))

def renameFilesBySHA1Digest(listOfFiles, directoryPath):

    for file in listOfFiles:
        try:
            hash_sha1 = hashlib.sha1()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha1.update(chunk)
            newFilenameFullPath = os.path.join(directoryPath, hash_sha1.hexdigest())
            os.rename(file, newFilenameFullPath)
        except Exception as error:
            print('renameFilesBySHA1Digest Error ... %s' % (error))

def renameFilesBySHA256Digest(listOfFiles, directoryPath):

    for file in listOfFiles:
        try:
            hash_sha256 = hashlib.sha256()
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            newFilenameFullPath = os.path.join(directoryPath, hash_sha256.hexdigest())
            os.rename(file, newFilenameFullPath)
        except Exception as error:
            print('renameFilesBySHA256Digest Error ... %s' % (error))

### ARGPARSE ###
parser = argparse.ArgumentParser(description='PERename - Rename all PE files in a directory')
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')
required.add_argument('-i', '--input', type=str, help='full directory path')
optional.add_argument('-m', '--modify', type=str, help='modification types (compilation, md5, sha1, sha256) - DEFAULT: md5', default='md5')
parseArgs = parser.parse_args()

if(parseArgs.input):
    directoryPath = ''
    if(parseArgs.input):
        directoryPath = parseArgs.input
    else:
        print('No directory path provided.')
        exit(1)

    listOfFiles = verificationSteps(directoryPath)

    if(parseArgs.modify == 'compilation'):
        renameFilesByCompilationTimes(listOfFiles, directoryPath)
    elif(parseArgs.modify == 'md5'):
        renameFilesByMD5Digest(listOfFiles, directoryPath)
    elif(parseArgs.modify == 'sha1'):
        renameFilesBySHA1Digest(listOfFiles, directoryPath)
    elif(parseArgs.modify == 'sha256'):
        renameFilesBySHA256Digest(listOfFiles, directoryPath)
    else:
        print('Incorrect modify selection.')
        exit(1)