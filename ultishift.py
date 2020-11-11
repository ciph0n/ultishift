import hashlib, base64, string, pyDes, os, yaml, shutil, random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# Text Message Encryption:
# text -> AES-256 [pass] -> base64 -> cipher -> pydes -> base64 -> cipher -> AES [math pass gen] -> cipher || -> AES [dynamic pass with GPGKeys] -> cipher

# File Encryption:
# file bytes -> hex -> AES [filekey-config-pass] -> cipher -> cipher 

path = os.getenv("APPDATA")
version = 'CReader-3'
bigprivatekey = ''
hexadata1 = ''
hexadata2 = ''
desdata1 = ''
desdata2 = ''
filekey = ''

def fileintegrity():
    # define success rate
    passed = 0
    failed = 0

    # declare config file contents
    configfile = 'class:'\
            f'\n    - identification: {version}'\
        '\nprivate:'\
            '\n    - privatekey: [please_insert_a_excessively_long_key]'\
        '\nhex:'\
            '\n    - hexdata1: [please_insert_hex_string]'\
            '\n    - hexdata2: [please_insert_different_hex_string]'\
        '\ndesencrypt:'\
            '\n    - desdata1: [insert_8_characters_and_number_string]'\
            '\n    - desdata2: [insert_32_characters_and_number_string]'\
        '\nfile:'\
            '\n    - filekey: [unique_long_file_password]'

    # /ultishift
    if os.path.exists(f'{path}/ultishift') == True:
        passed += 1
    else:
        os.mkdir(f'{path}/ultishift')
        failed += 1
    # /config
    if os.path.exists(f'{path}/ultishift/config') == True:
        passed += 1
        # /config.yaml
        if os.path.isfile(f'{path}/ultishift/config/config.yaml'):
            passed += 1
        else:
            failed += 1
            with open(f'{path}/ultishift/config/config.yaml','w') as file:
                file.write(configfile)
            file.close()
    else:
        failed += 1
        # make the folder 'config'
        os.mkdir(f'{path}/ultishift/config')
        with open(f'{path}/ultishift/config/config.yaml','w') as file:
            file.write(configfile)
        file.close()

    # /fileconvert
    if os.path.exists(f'{path}/ultishift/fileconvert') == True:
        passed += 1
        # /fileconvert/encrypted
        if os.path.exists(f'{path}/ultishift/fileconvert/encrypted') == True:
            passed += 1
            # /fileconvert/decrypted
            if os.path.exists(f'{path}/ultishift/fileconvert/decrypted') == True:
                passed += 1
            else:
                failed += 1
                os.mkdir(f'{path}/ultishift/fileconvert/decrypted')
        else:
            failed += 1
            os.mkdir(f'{path}/ultishift/fileconvert/encrypted')
    else:
        failed += 1
        os.mkdir(f'{path}/ultishift/fileconvert')

    # create the read stream 
    stream = open(f'{path}/ultishift/config/config.yaml', 'r')
    # load the yaml data with the loader
    data = yaml.load(stream, Loader=yaml.FullLoader)

    # change global variable data
    global theid, bigprivatekey, hexadata1, hexadata2, desdata1, desdata2, filekey
    theid = data['class'][0]['identification']
    bigprivatekey = data['private'][0]['privatekey']
    hexadata1 = data['hex'][0]['hexdata1']
    hexadata2 = data['hex'][1]['hexdata2']
    desdata1 = data['desencrypt'][0]['desdata1']
    desdata2 = data['desencrypt'][1]['desdata2']
    filekey = data['file'][0]['filekey']

    # version verification
    if os.path.isfile(f'{path}/ultishift/config/config.yaml') == True:
        if theid != version:
            print('(FileIntegrity): Incorrect version\n(FileIntegrity): Rebuilding new config.yaml..')
            shutil.copyfile(f'{path}/ultishift/config/config.yaml' , f'{path}/ultishift/config/config.yaml.old')
            with open(f'{path}/ultishift/config/config.yaml','w') as file:
                file.write(configfile)
            file.close()
        else:
            print(f'(FileIntegrity): Correct version!\n(FileIntegrity): Passed: {passed} | Failed: {failed}')
    
    # if not passed 5 times, display building data
    if passed != 6:
        print('--------------------------------------------\n(FileIntegrity): Building missing data...\n--------------------------------------------\n')
        fileintegrity()

def privatekey(request):
    if request == 'privatekey':
        newkey = f'{hexadata1}DtQLqY9kSaoO9B1TsoGWZp9LyG22/K86gIexwv4{hexadata2}WpvA/rO1tlvyyXU9yo/KJjIyQ+GwV80jCldrAinERthk/tqkcz0w7fdt'
        numberkey = (len(newkey)*newkey) * 3
        secretkey = (f'{numberkey}{bigprivatekey}oa7kGn2LXElrYq9oa3qPILJkLiaGtNe4JpXxG7udyaTVWgb1n1L54sIyVSnROErfQzZFVsjoCHfKMNGoBMpaTRBcwtXTslmm8Q4apdXF5gtoc7311KmilWSehtbue5OxMoPuBlCUSr1Q{numberkey}') * 35
        return secretkey
    elif request == 'iv':
        return 'E3h4G9d9gja='
    elif request == 'key':
        return 'W5347o94aA89633UB4246E456A657R67'

def encryptor(message, password):
    # encrypt the data with AES
    encrypteddata = aesencrypt(message, password, decrypt=False)

    # cipher the information
    important = cencrypt(encrypteddata, 86, decrypt=False)
    
    # cipher the information again
    bigkey = cencrypt(important, 45, decrypt=False)

    # Building the information for TripleDes
    strToEncrypt = bigkey

    k = pyDes.triple_des(
        base64.b64decode(privatekey('key')),
        mode=pyDes.CBC,
        IV=base64.b64decode(privatekey('iv')),
        padmode=pyDes.PAD_PKCS5
    )
    encryptedStr = k.encrypt(strToEncrypt)

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
    return print(f'\n\nPublic Key:\n```{publickey}```')

def decryptor(msg, password):
    # lets reverse this message
    topmessage = cencrypt(msg, 28, decrypt=True)

    # decrypt the aes using the privatekey 
    uncleaned = aesdecrypt(topmessage, password, useprivatekey=True)

    # shift the characters back
    unciphered = cencrypt(uncleaned, 54, decrypt=True)

    # clean the base64 off of the ciphered data
    cleaned = base64.b64decode(unciphered)

    k = pyDes.triple_des(
        base64.b64decode(privatekey('key')),
        mode=pyDes.CBC,
        IV=base64.b64decode(privatekey('iv')),
        padmode=pyDes.PAD_PKCS5
    )
    decryptedStr = k.decrypt(cleaned)
    decryptedStr = bytes.decode(decryptedStr)

    # lets reverse this message
    bigkey = cencrypt(decryptedStr, 45, decrypt=True)

    # deciphering the ciphered message
    deimportant = cencrypt(bigkey, 86, decrypt=True)  

    # decrypt the aes without private key
    decrypted = aesdecrypt(deimportant, password, useprivatekey=False)

    return print(f'\n\nDecrypted data: {decrypted}')

def aesencrypt(message, password, decrypt=False):
    if decrypt == False:
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
    acipher_text = privatearray[0]
    asalt = privatearray[1]
    anonce = privatearray[2]
    atag = privatearray[3]

    # decode the dictionary entries from base64
    ksalt = base64.b64decode(asalt)
    kcipher_text = base64.b64decode(acipher_text)
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
    kdecrypted = kcipher.decrypt_and_verify(kcipher_text, ktag)
 
    return bytes.decode(kdecrypted)

def cencrypt(text, key=17, decrypt=False):
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + " " + string.punctuation
    if decrypt==True:
        key = len(characters) - key

    table = str.maketrans(characters, characters[key:] + characters[:key])
    cipheredtable = text.translate(table)
    return cipheredtable

def smallcrypt(message, password, decrypt=False):
    if decrypt == False:
        # encrypt the data with AES
        encrypteddata = aesencrypt(message, password, decrypt=False)

        # cipher the information
        important = cencrypt(encrypteddata, 86, decrypt=False)
        
        # cipher the information again
        return cencrypt(important, 45, decrypt=False)
    else:
        # lets reverse this message
        bigkey = cencrypt(message, 45, decrypt=True)

        # deciphering the ciphered message
        deimportant = cencrypt(bigkey, 86, decrypt=True)  

        # decrypt the aes without private key
        return aesdecrypt(deimportant, password, useprivatekey=False)

def fileencrypt(filename, extension):
    outext = str(input('Insert output file extension [pref: .bin]: '))
    if os.path.isfile(f'{path}/ultishift/fileconvert/{filename}{extension}'):
        with open(f'{path}/ultishift/fileconvert/{filename}{extension}','rb') as file:
            filedata = file.read()
        # convert the original file data to hex
        hexdata = filedata.hex()

        # AES encrypt the hex data
        output = smallcrypt(hexdata, filekey, decrypt=False)

        # output the file as bin
        with open(f'{path}/ultishift/fileconvert/encrypted/{filename}{outext}','w') as newfile:
            newfile.write(output)
        print('File has been encrypted!\n')

def filedecrypt(filename, extension):
    outext = str(input('Insert the real decrypted file extension [pref: .exe]: '))
    if os.path.isfile(f'{path}/ultishift/fileconvert/{filename}{extension}'):
        with open(f'{path}/ultishift/fileconvert/{filename}{extension}','r') as file:
            filedata = file.read()

        # decrypt the AES
        output = smallcrypt(filedata, filekey, decrypt=True)

        # decode it from hex back to bytes
        output = bytes.fromhex(output)

        # out file back to bytes
        with open(f'{path}/ultishift/fileconvert/decrypted/{filename}{outext}','wb') as newfile:
            newfile.write(output)
        print('File has been decrypted!\n')

def main():
    text = input('--------------------------------------------\n|| Encryption Center || github.com/ciph0n ||\n--------------------------------------------\n[A] Encrypt\n[B] Decrypt\n[C] File Encrypt\n[D] File Decrypt\n[E] Config Loader\n\nSelection: ')
    if text.lower() == 'a': # message encrypt only
        password = input('Password: ')
        data = str(input('Text2Encrypt: '))
        encrypted = encryptor(data, password)
    elif text.lower() == 'b': # message decrypt only
        password = input('Password: ')
        data = str(input('Text2Decrypt: '))
        decrypted = decryptor(data, password)
    elif text.lower() == 'c': # file encrypt only
        data = str(input('Filename2Encrypt: '))
        filext = str(input('File extension [.exe|.*]: '))
        encrypted = fileencrypt(data, filext)
    elif text.lower() == 'd': # file decrypt only
        data = str(input('Filename2Decrypt: '))
        filext = str(input('File extension [.exe|.*]: '))
        decrypted = filedecrypt(data, filext)
    elif text.lower() == 'e': # config loader
        data = str(input('Filename2Load: '))
        #decrypted = filedecrypt(data, filext)
    else:
        exit()
    main()
        
if __name__ == '__main__':
    fileintegrity()
    main()
