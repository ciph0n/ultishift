# Ultishift

Ultishift is an encryption method utilizing a list of encryption and cipher methods such as AES, TripleDes, Caesar Cipher, and Base64. Use cases range from general encryption of messages from one peer to another or full on file encryption. Peers can define keys within their secure config files to encrypt or decrypt a message or file from another peer.

## How to build/run from source

### Requirements

* Python3

### Build Steps
```bash
git clone https://github.com/ciph0n/ultishift
pip install -r requirements.txt
pyinstaller main.py --onefile --name ultishift
```
## How to use

Run the binary to run the application.

In the new terminal window you have several options

### Encrypt

Takes a plaintext string and encrypts it, you can add a password for a more secure message (Recommended).

### Decrypt

Takes an already encrypted string and decrypts back into plaintext. If there was a password provided with the message you must add that password for the decryption to take place. You must also have the same config for your peer.

### File Encrypt

Takes a file of any kind, encrypts the contents, and outputs it to a custom filetype.

To encrypt a file, you must put the encrypted file in `%APPDATA%/ultishift/fileconvert`, run the encrypt and it will output to `%APPDATA%/ultishift/fileconvert/encrypted`

### File Decrypt

Takes an encrypted file and decrypts the contents back into the original filetype. Your peer must tell you what the original filetype is in order to decrypt it correctly.

To decrypt a file, you must put the encrypted file in `%APPDATA%/ultishift/fileconvert`, run the decrypt and it will output to `%APPDATA%/ultishift/fileconvert/decrypted`

### Config Loader

Loads individual configration files from the `%APPDATA%/ultishift/config` folder, you can have several files and each can be loaded individually. You can only have one config file loaded at a time, but you can store as many config files in the directory as you wish.

## Setting up the config (Advanced)

Starting Ultishift for the first time creates a clean slate for a config file. The file is located in `%APPDATA%/ultishift/config`.

This is the `defaultconfig.yaml` file that is auto-generated:

```yaml
class:
    - identification: CReader-6
private:
    - privatekey: "[please_insert_a_excessively_long_key]"
    - randomdata1: "[please_insert_a_excessively_long_key]"
    - randomdata2: "[please_insert_a_excessively_long_key]"
desencrypt:
    - desdata1: 11charsnumb
    - desdata2: 32randommixedcharacterandnumbers
file:
    - filekey: "filekey[please_insert_a_excessively_long_key]"
discord:
    - keyformatting: False
    - peerid: 123456789123456789
```

*This config file was released on version: `CReader-6`.*

The config itself is supposed to be shared in its complete form to your peer who you want to encrypt/decrypt files and other messages from them. It's best use to have a config file per peer, each containing its own data.

Each individual section of the config is explained below.

### Class

**Do not modify this part of the file, as this is used for version verification for the application.**

By modifying this header, the applicaion will mark the file as corrupt and automatically generate the default configuration file. This does not delete the file, as it will just rename the filetype.

note: having a key length over 100+ characters for pkey/rd1/rd2 may take longer to generate but is more secure.

### Private

Any of these private keys are required in order for message encryption/decryption, you should have these keys 100+ characters.

* `privatekey: "[please_insert_a_excessively_long_key]"`

The `privatekey` is best to be generated 100+ characters using case sensitive characters, numbers, and symbols.

* `randomdata1: "[please_insert_a_excessively_long_key]"`
* `randomdata2: "[please_insert_a_excessively_long_key]"`

`randomdata1` and `randomdata2` are both used in the encryption/decryption process to make the 'secret key'. This essentially acts as two salts to the private key making the key way more complex.

By having a key length over 100+ characters for the `privatekey`, `randomdata1`, and `randomdata2` will increase the security of the message at the cost of performace for generating a message.

### Desencrypt

**The keys for this section must be alpha-numeric (A-z) and contain numbers, and must be the required length.**

* `desdata1: 11charsnumb`

desdata1 is required to be 11 characters long, and the best practice is to have it randomly generated using numbers and case sensitive without symbols.

* `desdata2: 32randommixedcharacterandnumbers`

desdata2 is required to be 32 characters long, and the best practice is to have it randomly generated using numbers and case sensitive without symbols.

### File

* `filekey: "filekey[please_insert_a_excessively_long_key]"`

You can encrypt/decrypt a file of any length, and this will be the private key for file encryption/decryption that will allow your peer to encrypt/decrypt a file with. 

### Discord Embeds

* `keyformatting: False`

This formats the output for [markdown](https://guides.github.com/features/mastering-markdown/#what) in a [quote block](https://docs.github.com/en/free-pro-team@latest/github/writing-on-github/basic-writing-and-formatting-syntax#quoting-code), where you can copy and paste the output string of text without possibly ruining the message in popular chatting applications such as Discord, Slack, Microsoft Teams, etc.

`False` does not output the encrypted message into markdown.

`True` outputs the encrypted message into markdown.

### Discord Message Notifier

* `peerid: 123456789123456789`

You can specify your peers' Discord user ID here, where the application will automatically generate a message for you to copy and paste in a Discord chat.

If you're using a group shared config, you can add multiple peers such as: `peerid1,peerid2,etc`.

To disable this, remove the `peerid` contents.
