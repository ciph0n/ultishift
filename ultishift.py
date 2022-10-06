import datetime, hashlib, base64, string, pyDes, yaml, shutil, re, sys, os
from dotenv import dotenv_values
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

# declare global variables
version = 'CReader-6'
loaded_config = None
config_filename = 'defaultconfig.ults'
path = "C:\\Z_VSC\\ultishift-main\\test\\"
pathList = [f'{path}/ultishift', f'{path}/ultishift/fileconvert', f'{path}/ultishift/notes', f'{path}/ultishift/fileconvert/encrypted', f'{path}/ultishift/fileconvert/decrypted', f'{path}/ultishift/config']
fileList = [f'{path}/ultishift/config/defaultconfig.ults']
defaultData = ['"[please_insert_a_excessively_long_key]"', '"[please_insert_a_excessively_long_key]"', '"[please_insert_a_excessively_long_key]"', '11charsnumb', '32randommixedcharacterandnumbers', '"filekey[please_insert_a_excessively_long_key]"', '123456789123456789']

def fileintegrity():
    global path, loaded_config#, version, config
    # define success rate
    passed = 0
    failed = 0

    # declare config file contents
    configfile = f"config_version={version}\n"\
        "randomdata1=[please_insert_a_excessively_long_key]\n"\
        "randomdata2=[please_insert_a_excessively_long_key]\n"\
        "desdata1=11charsnumb\n"\
        "desdata2=32randommixedcharacterandnumbers\n"\
        "filekey=filekey[please_insert_a_excessively_long_key]\n"\
        "discord_keyformatting=False\n"\
        "discord_peerid=123456789123456789"

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

    # version verification
    loaded_config = dotenv_values(f'{path}\\ultishift\\config\\defaultconfig.ults')
    
    if os.path.isfile(f'{path}\\ultishift\\config\\defaultconfig.ults') == True:
        if loaded_config['config_version'] != version:
            print('(FileIntegrity): Incorrect version!\n(FileIntegrity): Rebuilt the default config.')
            shutil.copyfile(f'{path}\\ultishift\\config\\defaultconfig.ults' , f'{path}\\ultishift\\config\\defaultconfig.ults.old')
            with open(f'{path}\\ultishift\\config\\defaultconfig.ults','w') as file:
                file.write(configfile)
            file.close()
    
    try:
        configloader(config_filename, noexceptions=False)
    except:
        # print(Exception.with_traceback())
        print('(FileIntegrity): \'defaultconfig.yaml\' seems to be broken.\n(FileIntegrity): Rebuilding new config.ults..')
        shutil.copyfile(f'{path}\\ultishift\\config\\defaultconfig.ults' , f'{path}\\ultishift\\config\\defaultconfig.ults.broken')
        with open(f'{path}\\ultishift\\config\\defaultconfig.ults','w') as file:
            file.write(configfile)
        file.close()

def configloader(filename, noexceptions=False):
    try:
        # create the read stream
        cl = dotenv_values(f'{path}\\ultishift\\config\\{filename}.ults')
        print(cl['config_version'])
    except FileNotFoundError:
        return print(f'[ERROR] (ConfigLoader): \'{filename}\' doesn\'t exist.')
    except KeyError:
        return print(f'[ERROR] (ConfigLoader): \'{filename}\' is broken. Is the file up to date with the defaultconfig?')
    
    # load the yaml data with the loader
    # cl = yaml.load(stream, Loader=yaml.FullLoader)

    if cl['config_version'] == version:
        # check desdata
        try:
            if len(cl['desdata1']) != 11:
                if noexceptions == True:
                    return print(f'[ERROR] (ConfigLoader): \'desdata1\' has an invalid length. It must be 11 characters long.\n[ERROR] (ConfigLoader): Config has been reverted.')
                print(f'[ERROR] (ConfigLoader): \'desdata1\' has an invalid length. It must be 11 characters long.')
                raise ValueError
            elif len(cl['desdata2']) != 32:
                if noexceptions == True:
                    return print(f'[ERROR] (ConfigLoader): \'desdatay2\' has an invalid length. It must be 32 characters long.\n[ERROR] (ConfigLoader): Config has been reverted.')
                raise ValueError
            elif len(cl['desdata1']) == 11:
                desmatch = re.search(r'^[^\W_]{3,48}$', cl['desdata1'])
                if desmatch == None:
                    if noexceptions == True:
                        return print(f'[ERROR] (ConfigLoader): \'desdata1\' contains non alphabetical and numerical data.\n[ERROR] (ConfigLoader): Config has been reverted.')
                    raise ValueError
            elif len(cl['desdata2']) == 32:
                desmatch = re.search(r'^[^\W_]{3,48}$', cl['desdata2'])
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
            if len(cl['privatekey']) != 0: 
                pass
            elif len(cl['randomdata1']) != 0:
                pass
            elif len(cl['randomdata2']) != 0:
                pass
        except:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'private\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise ValueError

        # check file data
        try:
            if len(cl['filekey']) != 0:
                pass
        except:
            if noexceptions == True:
                return print(f'[ERROR] (ConfigLoader): \'filekey\' has missing data.\n[ERROR] (ConfigLoader): Config has been reverted.')
            raise ValueError

        # check discord data
        try:
            if cl['keyformatting'] == True:
                newdiscordformat = '```'
            elif cl['keyformatting'] == False:
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
            if len(str(cl['peerid'])) <= 17:
                print(f'[WARNING] (ConfigLoader): \'peerid\' hasn\'t been set or is invalid.')
            elif len(str(cl['peerid'])) == 18:
                lettersinid = re.search(r'\d{18}', str(cl['peerid']))
                if lettersinid == None:
                    print(f'[WARNING] (ConfigLoader): \'peerid\' is an invalid Discord userid.')
            elif len(str(cl['peerid'])) >= 18:
                lettersinid = re.search(r'\d{18}', str(cl['peerid']))
                if lettersinid == None:
                    print(f'[WARNING] (ConfigLoader): \'peerid\' is an invalid Discord userid.')
                if str(cl['peerid']).__contains__(','):
                    global idarray, peerid
                    idarray = str(cl['peerid']).split(',')
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
        
        global desdata1, desdata2, bigprivatekey, randomdata1, randomdata2, filekey, discordformat, config_filename
        desdata1 = cl['desdata1']
        desdata2 = cl['desdata2']
        bigprivatekey = cl['privatekey']
        randomdata1 = cl['randomdata1']
        randomdata2 = cl['randomdata2']
        filekey = cl['filekey']
        discordformat = newdiscordformat
        peerid = str(f"<@{cl['peerid']}>")
        config_filename = filename

        configData = [bigprivatekey, randomdata1, randomdata2, desdata1, desdata2, filekey, peerid]
        
        defaultcheck = 0
        for data in defaultData:
            for input in configData:
                if data == input:
                    defaultcheck += 1
        
        if peerid == '<@None>':
            peerid = ''

        if defaultcheck != 0:
            print(f'[WARNING] (ConfigLoader): You\'re still using default config data in \'{config_filename}\'.')

        return print(f'(ConfigLoader): \'{config_filename}\' has been successfully loaded.')
    else:
        if noexceptions == True:
            return print(f'(ConfigLoader): Incorrect Version!\n(ConfigLoader): Reverting back to {config_filename}.')
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

    try:
        k = pyDes.triple_des(
            base64.b64decode(privatekey('key')),
            mode=pyDes.CBC,
            IV=base64.b64decode(privatekey('iv')),
            padmode=pyDes.PAD_PKCS5
        )
        encryptedStr = k.encrypt(bigkey)
    except:
        return print(f'[ERROR] (Encryptor): \'desencrypt\' seems to contain symbols.')

    # setting it to base64
    decodeddes = bytes.decode(base64.b64encode(encryptedStr))

    # cipher
    desunciphered = cencrypt(decodeddes, 54, decrypt=False)

    # use the dynamic 
    corekey = aesencrypt(desunciphered, privatekey('privatekey'))

    # cipher the dynamicly generated AES
    publickey = cencrypt(corekey, 28, decrypt=False)

    # exportable and encrypted message
    if discordformat == '```' and peerid != '':
        if password != '':
            return f'{peerid} `{password}`\n{discordformat}{publickey}{discordformat}'
        return f'{peerid}\n{discordformat}{publickey}{discordformat}'
    return f'{discordformat}{publickey}{discordformat}'

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

    # exportable and decrypted message
    return decrypted

def aesencrypt(message, password):
    # generate salt
    salt = get_random_bytes(AES.block_size)

    # generate the private key via salt/pass
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    
    # create the cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # decrypt the cipher text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))
    
    # format the data
    data = f'{base64.b64encode(cipher_text).decode("utf-8")},{base64.b64encode(salt).decode("utf-8")},{base64.b64encode(cipher_config.nonce).decode("utf-8")},{base64.b64encode(tag).decode("utf-8")}'

    return data

def aesdecrypt(encryptedmessage, password, useprivatekey=False):
    # create an array and split strings
    privatearray = encryptedmessage.split(',')

    # {cipherdata:privatearray[0], salt:privatearray[1], nonce:privatearray[2], tag:privatearray[3]}

    # generate the private key via salt/pass
    if useprivatekey == True:
        kprivate_key = hashlib.scrypt(privatekey('privatekey').encode(), salt=base64.b64decode(privatearray[1]), n=2**14, r=8, p=1, dklen=32)
    else:
        kprivate_key = hashlib.scrypt(password.encode(), salt=base64.b64decode(privatearray[1]), n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    kcipher = AES.new(kprivate_key, AES.MODE_GCM, nonce=base64.b64decode(privatearray[2]))

    # decrypt the cipher text
    kdecrypted = kcipher.decrypt_and_verify(base64.b64decode(privatearray[0]), base64.b64decode(privatearray[3]))
 
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

def np_encrypt(filename, data, password):
    """ Establishing a byte array to store encrypted text in """
    byte_msg_arr = []
    for bytes in encryptor(data, password).encode('utf-8'):
        byte_msg_arr.append(bytes)
    
    """ Exporting the note without a password """
    if password == '':
        file = open(f'{path}/ultishift/notes/{filename}.ults', 'w')
        file.write('\n')
        for bytes in byte_msg_arr:
            file.write(f'{str(bytes)} ')
        file.close()
    else:
        file = open(f'{path}/ultishift/notes/{filename}.ults', 'w')
        
        byte_pass_arr = []
        for bytez in encryptor(password, '').encode('utf-8'):
            byte_pass_arr.append(bytez)
        
        for bytez in byte_pass_arr:
            file.write(f'{str(bytez)} ')
        file.write('\n')

        for bytes in byte_msg_arr:
            file.write(f'{str(bytes)} ')
        file.close()

    return f'SUCCESS: "{filename}.ults" has been created!'

def np_decrypt(filename):
    try:
        file = open(f'{path}/ultishift/notes/{filename}.ults', 'r').readlines()
    except FileNotFoundError:
        return f'[X] ERROR: "{filename}.ults" was not found.'
    counter = 0
    password = ''
    byte_pass_arr = []
    byte_msg_arr = []
    for line in file:
        if counter == 0:
            if len(line) > 1:
                """ Remove spaces from the line """
                line_data = line.split(' ')
                line_data.pop(-1)

                """ Establishing a byte array to store encrypted password text in """
                for data in line_data:
                    byte_pass_arr.append(int(data))
                
                """ Decrypt the password given """
                password = decryptor(''.join(map(chr, bytes(byte_pass_arr))), '')
            else:
                password = ''
        else:
            """ Remove spaces from the line """
            line_data = line.split(' ')
            line_data.pop(-1)

            """ Establishing a byte array to store encrypted text in """
            for data in line_data:
                byte_msg_arr.append(int(data))
        counter += 1

    """ Decrypting the note """
    return decryptor(''.join(map(chr, bytes(byte_msg_arr))), password)

def np_list(directory):
    notes = ''
    for files in os.listdir(directory):
        if '.ults' or '.yaml' in files:
            notes += f'[#] {files}\n'
    return notes

def main():
    try:
        text = input(f'{"-"*44}\n--> Ultishift | Loaded: {config_filename}\n{"-"*44}\n[A] Encrypt\n[B] Decrypt\n[C] File Encrypt\n[D] File Decrypt\n[E] Notepad - Encrypt\n[F] Notepad - Decrypt\n[G] Config Loader\n[X] Exit\n\nSelection: ')
        if text.lower() == 'a': # message encrypt only
            password = input('Password: ')
            data = str(input('Text2Encrypt: '))
            print(f'\n\n{encryptor(data, password)}')
        elif text.lower() == 'b': # message decrypt only
            password = input('Password: ')
            data = str(input('Text2Decrypt: '))
            print(f'\n\n{decryptor(data, password)}')
        elif text.lower() == 'c': # file encrypt only
            data = str(input('Filename2Encrypt: '))
            filext = str(input('File extension [.*]: '))
            fileencrypt(data, filext)
        elif text.lower() == 'd': # file decrypt only
            data = str(input('Filename2Decrypt: '))
            filext = str(input('File extension [.bin]: '))
            filedecrypt(data, filext)
        elif text.lower() == 'e': # notepad - encrypt
            print(f'{"=="*10}\nNotes in Directory:\n{np_list(f"{path}/ultishift/notes")}')
            filename = input('[Encryption] Filename [no ext]: ')
            if len(filename) != 0:
                password = input('Password: ')
                data = ''
                data += f'This note was written on: {datetime.datetime.now()}\n\n'
                while True:
                    msg = str(input('Done? Type: "::end"-> '))
                    if msg == '::end':
                        break
                    data += f'{msg}\n'
                print(f'\n{np_encrypt(filename, data, password)}')
            else:
                print('\n[ERROR] You cannot write a nameless note.')
        elif text.lower() == 'f': # notepad - decrypt
            print(f'{"=="*10}\nNotes in Directory:\n{np_list(f"{path}/ultishift/notes")}')
            filename = str(input('[Decryption] Filename [no ext]: '))
            if len(filename) != 0:
                print(f'\n{np_decrypt(filename)}')
            else:
                print('\n[ERROR] You cannot write a nameless note.')
        elif text.lower() == 'g': # config loader
            print(f'{"=="*10}\nConfigs in Directory:\n{np_list(f"{path}/ultishift/config")}')
            data = str(input('File2Load [name.yaml]: '))
            try:
                configloader(data, noexceptions=True)
            except PermissionError:
                print('\n[ERROR] Permission denied in "/config".')
        elif text.lower() == 'x':
            print('\nExiting..')
            sys.exit()
        main()
    except KeyboardInterrupt:
        print('x\n\nExiting..')
        
if __name__ == '__main__':
    fileintegrity()
    main()
