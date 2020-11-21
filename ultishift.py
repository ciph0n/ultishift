import hashlib, base64, string, pyDes, os, yaml, shutil, re, sys
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# declare global variables
path = os.getenv("APPDATA")
version = 'CReader-6'
pathList = [f'{path}/ultishift', f'{path}/ultishift/fileconvert', f'{path}/ultishift/fileconvert/encrypted', f'{path}/ultishift/fileconvert/decrypted', f'{path}/ultishift/config']
fileList = [f'{path}/ultishift/config/defaultconfig.yaml']
defaultData = ['"[please_insert_a_excessively_long_key]"', '"[please_insert_a_excessively_long_key]"', '"[please_insert_a_excessively_long_key]"', '11charsnumb', '32randommixedcharacterandnumbers', '"filekey[please_insert_a_excessively_long_key]"', '123456789123456789']

def fileintegrity():
    # define success rate
    passed = 0
    failed = 0

    # declare config file contents
    configfile = 'class:'\
            f'\n    - identification: {version}'\
        '\nprivate:'\
            '\n    - privatekey: "[please_insert_a_excessively_long_key]"'\
            '\n    - randomdata1: "[please_insert_a_excessively_long_key]"'\
            '\n    - randomdata2: "[please_insert_a_excessively_long_key]"'\
        '\ndesencrypt:'\
            '\n    - desdata1: 11charsnumb'\
            '\n    - desdata2: 32randommixedcharacterandnumbers'\
        '\nfile:'\
            '\n    - filekey: "filekey[please_insert_a_excessively_long_key]"'\
        '\ndiscord:'\
            '\n    - keyformatting: False'\
            '\n    - peerid: 123456789123456789'

    for path in pathList:
        if os.path.exists(path):
            passed += 1
        else:
            failed += 1
            os.mkdir(path)
    for file in fileList:
        if os.path.isfile(file):
            passed += 1
        else:
            failed += 1
            with open(file,'w') as data:
                data.write(configfile)
            data.close()

    # create the read stream 
    stream = open(f'{path}/defaultconfig.yaml', 'r')
    # load the yaml data with the loader
    data = yaml.load(stream, Loader=yaml.FullLoader)

    # version verification
    if os.path.isfile(f'{path}/defaultconfig.yaml') == True:
        if data['class'][0]['identification'] != version:
            print('(FileIntegrity): Incorrect version!\n(FileIntegrity): Rebuilt the default config.')
            shutil.copyfile(f'{path}/defaultconfig.yaml' , f'{path}/defaultconfig.yaml.old')
            with open(f'{path}/defaultconfig.yaml','w') as file:
                file.write(configfile)
            file.close()
    
    try:
        configloader('defaultconfig.yaml', noexceptions=False)
    except:
        print(Exception.with_traceback())
        print('(FileIntegrity): \'defaultconfig.yaml\' seems to be broken.\n(FileIntegrity): Rebuilding new config.yaml..')
        shutil.copyfile(f'{path}/defaultconfig.yaml' , f'{path}/defaultconfig.yaml.broken')
        with open(f'{path}/defaultconfig.yaml','w') as file:
            file.write(configfile)
        file.close()


def configloader(filename, noexceptions=False):
    try:
        # create the read stream
        stream = open(f'{path}/ultishift/config/{filename}', 'r')
    except FileNotFoundError:
        return print(f'[ERROR] (ConfigLoader): \'{filename}\' doesn\'t exist.')
    except KeyError:
        return print(f'[ERROR] (ConfigLoader): \'{filename}\' is broken. Is the file up to date with the defaultconfig?')
    
    # load the yaml data with the loader
    cl = yaml.load(stream, Loader=yaml.FullLoader)

    if cl['class'][0]['identification'] == version:
        # check desdata
        try:
            if len(cl['desencrypt'][0]['desdata1']) != 11:
                if noexceptions == True:
                    return print(f'[ERROR] (ConfigLoader): \'desdata1\' has an invalid length. It must be 11 characters long.\n[ERROR] (ConfigLoader): Config has been reverted.')
                print(f'[ERROR] (ConfigLoader): \'desdata1\' has an invalid length. It must be 11 characters long.')
                raise ValueError
            elif len(cl['desencrypt'][1]['desdata2']) != 32:
                if noexceptions == True:
                    return print(f'[ERROR] (ConfigLoader): \'desdatay2\' has an invalid length. It must be 32 characters long.\n[ERROR] (ConfigLoader): Config has been reverted.')
                raise ValueError
            elif len(cl['desencrypt'][0]['desdata1']) == 11:
                desmatch = re.search(r'^[^\W_]{3,48}$', cl['desencrypt'][0]['desdata1'])
                if desmatch == None:
                    if noexceptions == True:
                        return print(f'[ERROR] (ConfigLoader): \'desdata1\' contains non alphabetical and numerical data.\n[ERROR] (ConfigLoader): Config has been reverted.')
                    raise ValueError
            elif len(cl['desencrypt'][1]['desdata2']) == 32:
                desmatch = re.search(r'^[^\W_]{3,48}$', cl['desencrypt'][1]['desdata2'])
                if desmatch == None:
                    if noexceptions == True:
                        return print(f'[ERROR] (ConfigLoader): \'desdata2\' contains non alphabetical and numerical data.\n[ERROR] (ConfigLoader): Config has been reverted.')
                    raise ValueError
        except TypeError:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'desencrypt\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise TypeError
        
        # check private data
        try:
            if len(cl['private'][0]['privatekey']) != 0: 
                pass
            elif len(cl['private'][1]['randomdata1']) != 0:
                pass
            elif len(cl['private'][2]['randomdata2']) != 0:
                pass
        except:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'private\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise ValueError

        # check file data
        try:
            if len(cl['file'][0]['filekey']) != 0:
                pass
        except:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'filekey\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise ValueError

        # check discord data
        try:
            if cl['discord'][0]['keyformatting'] == True:
                newdiscordformat = '```'
            elif cl['discord'][0]['keyformatting'] == False:
                newdiscordformat = ''
            else:
                newdiscordformat = ''
                print(f'[WARNING] (ConfigLoader): \'discord\' has invalid data. It should contain \'True\' or \'False\'.\n[WARNING] (ConfigLoader): Defaulting value to False.')
        except TypeError:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'discord\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise TypeError
        
        # check discord peerid data
        try:
            if len(str(cl['discord'][1]['peerid'])) <= 17:
                print(f'[WARNING] (ConfigLoader): \'peerid\' hasn\'t been set or is invalid.')
            elif len(str(cl['discord'][1]['peerid'])) == 18:
                lettersinid = re.search(r'\d{18}', str(cl['discord'][1]['peerid']))
                if lettersinid == None:
                    print(f'[WARNING] (ConfigLoader): \'peerid\' is an invalid Discord userid.')
            elif len(str(cl['discord'][1]['peerid'])) >= 18:
                lettersinid = re.search(r'\d{18}', str(cl['discord'][1]['peerid']))
                if lettersinid == None:
                    print(f'[WARNING] (ConfigLoader): \'peerid\' is an invalid Discord userid.')
                if str(cl['discord'][1]['peerid']).__contains__(','):
                    global idarray, peerid
                    idarray = str(cl['discord'][1]['peerid']).split(',')
                    i = 0
                    peerid = ''
                    for data in idarray:
                        idarray.insert(i+1, data)
                        peerid += f'<@{data}> '
                        idarray.pop(i)
                        i += 1
                else:
                    print(f'[WARNING] (ConfigLoader): \'peerid\' is an invalid Discord userid.')
        except:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'discord\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise ValueError
        
        global desdata1, desdata2, bigprivatekey, randomdata1, randomdata2, filekey, discordformat, loadedfile
        desdata1 = cl['desencrypt'][0]['desdata1']
        desdata2 = cl['desencrypt'][1]['desdata2']
        bigprivatekey = cl['private'][0]['privatekey']
        randomdata1 = cl['private'][1]['randomdata1']
        randomdata2 = cl['private'][2]['randomdata2']
        filekey = cl['file'][0]['filekey']
        discordformat = newdiscordformat
        peerid = str(f"<@{cl['discord'][1]['peerid']}>")
        loadedfile = filename

        configData = [bigprivatekey, randomdata1, randomdata2, desdata1, desdata2, filekey, peerid]
        
        defaultcheck = 0
        for data in defaultData:
            for input in configData:
                if data == input:
                    defaultcheck += 1
        
        if peerid == '<@None>':
            peerid = ''

        if defaultcheck != 0:
            print(f'[WARNING] (ConfigLoader): You\'re still using default config data in \'{loadedfile}\'.')

        return print(f'(ConfigLoader): \'{loadedfile}\' has been successfully loaded.')
    else:
        if noexceptions == True:
            return print(f'(ConfigLoader): Incorrect Version!\n(ConfigLoader): Reverting back to {loadedfile}.')
        raise ValueError

def privatekey(request):
    if request == 'privatekey':
        newkey = f'{randomdata1}DtQLqY9kSaoO9B1TsoGWZp9LyG22/K86gIexwv4{randomdata2}WpvA/rO1tlvyyXU9yo/KJjIyQ+GwV80jCldrAinERthk/tqkcz0w7fdt'
        numberkey = (len(newkey)*newkey) * 3
        secretkey = (f'{numberkey}{bigprivatekey}oa7kGn2LXElrYq9oa3qPILJkLiaGtNe4JpXxG7udyaTVWgb1n1L54sIyVSnROErfQzZFVsjoCHfKMNGoBMpaTRB{numberkey}') * 35
        return secretkey
    elif request == 'iv':
        return f'{desdata1}='
    elif request == 'key':
        return f'{desdata2}'

def encryptor(message, password):
    # encrypt the data with AES
    encrypteddata = aesencrypt(message, password)

    # cipher the information
    important = cencrypt(encrypteddata, 86, decrypt=False)
    
    # cipher the information again
    bigkey = cencrypt(important, 45, decrypt=False)

    # Building the information for TripleDes
    strToEncrypt = bigkey

    try:
        k = pyDes.triple_des(
            base64.b64decode(privatekey('key')),
            mode=pyDes.CBC,
            IV=base64.b64decode(privatekey('iv')),
            padmode=pyDes.PAD_PKCS5
        )
        encryptedStr = k.encrypt(strToEncrypt)
    except:
        return print(f'[ERROR] (Encryptor): \'desencrypt\' seems to contain symbols.')

    # setting it to base64
    decodeddes = base64.b64encode(encryptedStr)
    decodeddes = bytes.decode(decodeddes)

    desunciphered = cencrypt(decodeddes, 54, decrypt=False)

    # create the password
    secretkey = privatekey('privatekey')

    # use the dynamic 
    corekey = aesencrypt(desunciphered, secretkey)

    # cipher the dynamicly generated AES
    publickey = cencrypt(corekey, 28, decrypt=False)

    # share this message
    if discordformat == '```' and peerid != '':
        if password != '':
            return print(f'Encrypted message: \n\n{peerid} `{password}`\n{discordformat}{publickey}{discordformat}')
        return print(f'Encrypted message: \n\n{peerid}\n{discordformat}{publickey}{discordformat}')
    return print(f'Encrypted message: \n\n{discordformat}{publickey}{discordformat}')

def decryptor(msg, password):
    # lets reverse this message
    topmessage = cencrypt(msg, 28, decrypt=True)

    # decrypt the aes using the privatekey 
    try:
        uncleaned = aesdecrypt(topmessage, password, useprivatekey=True)
    except:
        return print('\n[ERROR] Privatekey is incorrect.')

    # shift the characters back
    unciphered = cencrypt(uncleaned, 54, decrypt=True)

    # clean the base64 off of the ciphered data
    cleaned = base64.b64decode(unciphered)

    try:
        k = pyDes.triple_des(
            base64.b64decode(privatekey('key')),
            mode=pyDes.CBC,
            IV=base64.b64decode(privatekey('iv')),
            padmode=pyDes.PAD_PKCS5
        )
        decryptedStr = k.decrypt(cleaned)
        decryptedStr = bytes.decode(decryptedStr)
    except:
        return print('\n[ERROR] desencrypt data is incorrect.')

    # lets reverse this message
    bigkey = cencrypt(decryptedStr, 45, decrypt=True)

    # deciphering the ciphered message
    deimportant = cencrypt(bigkey, 86, decrypt=True)  

    try:
        # decrypt the aes without private key
        decrypted = aesdecrypt(deimportant, password, useprivatekey=False)
    except:
        return print('\n[ERROR] Password is incorrect.')

    return print(f'Decrypted message: \n\n{decrypted}')

def aesencrypt(message, password):
    # generate salt
    salt = get_random_bytes(AES.block_size)

    # generate the private key via salt/pass
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    
    # create the cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # decrypt the cipher text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))

    # encode the data in base64
    pciphertext = base64.b64encode(cipher_text).decode('utf-8')
    psalt = base64.b64encode(salt).decode('utf-8')
    pnonce = base64.b64encode(cipher_config.nonce).decode('utf-8')
    ptag = base64.b64encode(tag).decode('utf-8')
    
    # format the data
    data = f'{pciphertext},{psalt},{pnonce},{ptag}'

    return data

def aesdecrypt(encryptedmessage, password, useprivatekey=False):
    # create an array and split strings
    privatearray = encryptedmessage.split(',')

    # create the variables from the array
    acipherdata = privatearray[0]
    asalt = privatearray[1]
    anonce = privatearray[2]
    atag = privatearray[3]

    # decode the dictionary entries from base64
    ksalt = base64.b64decode(asalt)
    kcipherdata = base64.b64decode(acipherdata)
    knonce = base64.b64decode(anonce)
    ktag = base64.b64decode(atag)

    if useprivatekey == True:
        # develop the key
        secretkey = privatekey('privatekey')
        # generate the private key via salt/pass
        kprivate_key = hashlib.scrypt(
            secretkey.encode(), salt=ksalt, n=2**14, r=8, p=1, dklen=32)
    else:
        # generate the private key via salt/pass
        kprivate_key = hashlib.scrypt(
            password.encode(), salt=ksalt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    kcipher = AES.new(kprivate_key, AES.MODE_GCM, nonce=knonce)

    # decrypt the cipher text
    kdecrypted = kcipher.decrypt_and_verify(kcipherdata, ktag)
 
    return bytes.decode(kdecrypted)

def cencrypt(text, key=17, decrypt=False):
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + " " + string.punctuation
    if decrypt==True:
        key = len(characters) - key

    table = str.maketrans(characters, characters[key:] + characters[:key])
    cipheredtable = text.translate(table)
    return cipheredtable

def fileencrypt(filename, extension):
    outext = str(input('Insert output file extension [pref: .bin]: '))
    if outext == '':
        outext = '.bin'
        print('[WARNING] (FileEncrypt): File extension was not provided. Using default \'.bin\'.')
    if filename == '':
        return print('[ERROR] (FileEncrypt): You must provide a file name.')
    if os.path.isfile(f'{path}/ultishift/fileconvert/{filename}{extension}'):
        with open(f'{path}/ultishift/fileconvert/{filename}{extension}','rb') as file:
            filedata = file.read()
        # convert the original file data to hex
        hexdata = filedata.hex()

        # encrypt the data with AES
        encrypteddata = aesencrypt(hexdata, filekey)

        # cipher the information
        important = cencrypt(encrypteddata, 86, decrypt=False)

        # cipher the information again
        output = cencrypt(important, 45, decrypt=False)

        # output the file as bin
        with open(f'{path}/ultishift/fileconvert/encrypted/{filename}{outext}','w') as newfile:
            newfile.write(output)
        return print('(FileEncrypt): File has been encrypted!')
    else:
        return print(f'[ERROR] (FileEncrypt): \'{filename}{extension}\' doesn\'t exist.')

def filedecrypt(filename, extension):
    if filename == '':
        return print('[ERROR] (FileEncrypt): You must provide a file name.')
    if extension == '':
        extension = '.bin'
        print('[WARNING] (FileEncrypt): File extension was not provided. Using default \'.bin\'.')
    outext = str(input('Insert the real decrypted file extension [pref: .exe]: '))
    if os.path.isfile(f'{path}/ultishift/fileconvert/{filename}{extension}'):
        with open(f'{path}/ultishift/fileconvert/{filename}{extension}','r') as file:
            filedata = file.read()

        # lets reverse this message
        bigkey = cencrypt(filedata, 45, decrypt=True)

        # deciphering the ciphered message
        deimportant = cencrypt(bigkey, 86, decrypt=True)  

        try:
            # decrypt the aes without private key
            output = aesdecrypt(deimportant, filekey, useprivatekey=False)
        except:
            return print('\n[ERROR] Filekey is incorrect.')

        # decode it from hex back to bytes
        output = bytes.fromhex(output)

        # out file back to bytes
        with open(f'{path}/ultishift/fileconvert/decrypted/{filename}{outext}','wb') as newfile:
            newfile.write(output)
        return print('(FileEncrypt): File has been decrypted!')
    else:
        return print(f'[ERROR] (FileEncrypt): \'{filename}{extension}\' doesn\'t exist.')

def main():
    try:
        text = input(f'--------------------------------------------\n--> Ultishift | Loaded: {loadedfile}\n--------------------------------------------\n[A] Encrypt\n[B] Decrypt\n[C] File Encrypt\n[D] File Decrypt\n[E] Config Loader\n[X] Exit\n\nSelection: ')
        if text.lower() == 'a': # message encrypt only
            password = input('Password: ')
            data = str(input('Text2Encrypt: '))
            encryptor(data, password)
        elif text.lower() == 'b': # message decrypt only
            password = input('Password: ')
            data = str(input('Text2Decrypt: '))
            decryptor(data, password)
        elif text.lower() == 'c': # file encrypt only
            data = str(input('Filename2Encrypt: '))
            filext = str(input('File extension [.*]: '))
            fileencrypt(data, filext)
        elif text.lower() == 'd': # file decrypt only
            data = str(input('Filename2Decrypt: '))
            filext = str(input('File extension [.bin]: '))
            filedecrypt(data, filext)
        elif text.lower() == 'e': # config loader
            data = str(input('File2Load [name.yaml]: '))
            configloader(data, noexceptions=True)
        elif text.lower() == 'x':
            print('\nExiting..')
            sys.exit()
        main()
    except KeyboardInterrupt:
        print('x\n\nExiting..')
        
if __name__ == '__main__':
    fileintegrity()
    main()
