# -*- coding: utf-8 -*-

#******************************************************************************
# Copyright 2014 Khepry Software
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#******************************************************************************

import binascii
import configparser
import gnupg
import os
import sys

from pprint import pprint


# -------------------------------------------------------------------------
# "main" method
# -------------------------------------------------------------------------

def main():
    
    iniFilePath = "PyGpgHandler.ini"

    # define the temporary folder
    # that will hold the generated keys
    # and the encrypted/signature files
    tmpFolder = '~/temp'

    # GPG sub-folder that will hold
    # the generated RSA/DSA keys in a file
    gpgTestSubFolder = 'gpgTest'

    # TXT sub-folder that will
    # hold the generated test files
    txtTestSubFolder = 'txtTest'
    
    # The name of the GPG key file that
    # will hold the generated RSA and DSA keys
    gpgTestKeyFileName = 'gpgTestKeyFile.asc'

    # North Carolina Voters files can be used as test files
    # because they are approximate 70 columns in width and vary
    # vary from a low of 1,000 rows to over 7,000,000 rows.
    # The voter files can be downloaded from the following URL:
    #   ftp://alt.ncsbe.gov/data/

    # small-size
    # srcFileName = '~/temp/Voters/NC/ncvoter48.csv'

    # medium-size
    # srcFileName = '~/temp/Voters/NC/ncvoter92.csv'

    # largest-size
    # srcFileName = '~/temp/Voters/NC/NC_Voters_StateWide.csv'

    # tiny test file 
    srcFileName = 'testFile.txt'

    # define the RSA key's values    
    rsa_keyLength = 2048
    rsa_keyType = 'RSA'
    rsa_keyUsage = 'sign,encrypt,auth'
    rsa_email_address = 'gpg.rsax@mydomain.com'
    rsa_passphrase = 'rsa passphrase'
    
    # ASCII-armor the
    # encrypted or signed files?
    rsa_ascii_armor = True
 
    # define the DSA key's values 
    dsa_keyLength = 2048
    dsa_keyType = 'DSA'
    dsa_keyUsage = 'sign'
    dsa_email_address = 'gpg.dsax@mydomain.com'
    dsa_passphrase = 'dsa passphrase'
    

    # obtain any command-line arguments
    nextArg = ""
    for argv in sys.argv:
        
        if nextArg != "":
            if nextArg == "iniFilePath":
                iniFilePath = argv
            nextArg = ""
        else:
            if argv.lower() == "--iniFilePath":
                nextArg = "iniFilePath"
        
    # expand any leading tilde
    # to the user's home path
    iniFilePath = os.path.abspath(os.path.expanduser(iniFilePath))

    # if INI file path does not exist
    if not os.path.exists(iniFilePath):
        # output error message
        sys.stderr.write('iniFilePath does not exist: "%s"\n' % iniFilePath)
        # cease further processing
        return
    
    # obtain the settings
    # from the INI file path
    config = configparser.ConfigParser()
    config.optionxform = str #this will preserve the case of the section names
    config.read(iniFilePath)

    # obtain the default settings from the INI file
    tmpFolder = config['defaults'].get('tmpFolder', tmpFolder)
    gpgTestSubFolder = config['defaults'].get('gpgTestSubFolder', gpgTestSubFolder)
    gpgTestKeyFileName = config['defaults'].get('gpgTestKeyFileName', gpgTestKeyFileName)
    txtTestSubFolder = config['defaults'].get('txtTestSubFolder', txtTestSubFolder)

    # obtain the source file settings from the INI file
    srcFileName = config['srcSpecs'].get('srcFileName', srcFileName)
    
    # obtain RSA Specs settings from the INI file
    rsa_keyLength = int(config['rsaSpecs'].get('rsa_keyLength', rsa_keyLength))
    rsa_keyType = config['rsaSpecs'].get('rsa_keyType', rsa_keyType)
    rsa_keyUsage = config['rsaSpecs'].get('rsa_keyUsage', rsa_keyUsage)
    rsa_email_address = config['rsaSpecs'].get('rsa_email_address', rsa_email_address)
    rsa_passphrase = config['rsaSpecs'].get('rsa_passphrase', rsa_passphrase)
    rsa_ascii_armor = (config['rsaSpecs'].get('rsa_ascii_armor') == 'True')

    # obtain DSA Specs settings from the INI file
    dsa_keyLength = int(config['dsaSpecs'].get('dsa_keyLength', dsa_keyLength))
    dsa_keyType = config['dsaSpecs'].get('dsa_keyType', dsa_keyType)
    dsa_keyUsage = config['dsaSpecs'].get('dsa_keyUsage', dsa_keyUsage)
    dsa_email_address = config['dsaSpecs'].get('dsa_email_address', dsa_email_address)
    dsa_passphrase = config['dsaSpecs'].get('dsa_passphrase', dsa_passphrase)

    # expand the temporary folder's name    
    tmpFolderExpanded = os.path.expanduser(tmpFolder)
    
    # if necessary
    if not os.path.exists(tmpFolderExpanded):
        # create the temporary folder
        os.makedirs(tmpFolderExpanded)
    
    gpgTestFolder = os.path.join(tmpFolder, gpgTestSubFolder)
    gpgTestFolderExpanded = os.path.expanduser(gpgTestFolder)
    
    # if necessary
    if not os.path.exists(gpgTestFolderExpanded):
        # create the GPG test folder
        os.makedirs(gpgTestFolderExpanded)
    
    txtTestFolder = os.path.join(tmpFolder, txtTestSubFolder)
    txtTestFolderExpanded = os.path.expanduser(txtTestFolder)
    
    # if necessary
    if not os.path.exists(txtTestFolderExpanded):
        # create the TXT test folder
        os.makedirs(txtTestFolderExpanded)

    srcFileNameExpanded = os.path.expanduser(srcFileName)
    
    #verify that the source file does exist
    if not os.path.exists(srcFileNameExpanded):
        sys.stderr.write("SRC file does NOT exist: %s\n" % srcFileName)
        return
        
    # if a folder was not specified
    if os.path.dirname(gpgTestKeyFileName) == '':        
        # pre-pend the GPG Test folder to the GPG Test key file name
        gpgTestKeyFileName = os.path.join(gpgTestFolder, gpgTestKeyFileName)
        
    # derive the GPG Test keys file name
    gpgTestKeyFileNameExpanded = os.path.expanduser(gpgTestKeyFileName)
    
    # if necessary
    if not os.path.exists(os.path.dirname(gpgTestKeyFileNameExpanded)):
        # create the folder for
        # the GPG Test key file
        os.makedirs(gpgTestKeyFileExpanded)

    # derive the future encrypted-and-signed file's name
    rsaFileName = os.path.join(txtTestFolderExpanded, os.path.basename(srcFileName))

    if rsa_ascii_armor:
        rsaFileName += '.asc'
    else:
        rsaFileName += '.gpg'

    # derive the future signature file's name
    dsaFileName = rsaFileName + '.sig'

    
    # ---------------------------------------------------------------------
    # Clean out the gpgTestFolder
    # ---------------------------------------------------------------------

    # if the GPG Test folder
    # is within the temporary folder
    if gpgTestFolder.startswith(tmpFolder):
        # recursively clear it
        os.system('rm -rf %s' % gpgTestFolderExpanded)

    # ---------------------------------------------------------------------
    # Initialize the GPG object
    # that will be used to perform
    # all cryptographic operations
    # throughout this program
    # ---------------------------------------------------------------------

    gpg = gnupg.GPG(gnupghome=gpgTestFolderExpanded)
    
    # ---------------------------------------------------------------------
    # Generate an RSA key
    # ---------------------------------------------------------------------
    # NOTE: On a virtual machine the "Generate a RSA key" logic
    # may take a **long** time to generate a key due to the
    # routine NOT being able to obtain enough system entropy.
    # Please see the "Performance Issues" sub-section under the
    # "Key Management" section in the following article
    # for an explanation as to why:
    #   https://pythonhosted.org/python-gnupg/
    # on Linux systems, using "haveged" seems to ameloriate this:
    #   sudo apt-get install haveged
    # ---------------------------------------------------------------------
    
    print ("Generate a RSA key")
   
    rsa_data = gpg.gen_key_input(name_email=rsa_email_address,
                                    key_type=rsa_keyType,
                                    key_length=rsa_keyLength,
                                    key_usage=rsa_keyUsage,
                                    passphrase=rsa_passphrase)
    rsa_key = gpg.gen_key(rsa_data)
    print ("RSA Key: %s" % rsa_key.fingerprint)
   
    # ---------------------------------------------------------------------
    # Generate a DSA key
    # ---------------------------------------------------------------------
    # NOTE: On a virtual machine the "Generate a DSA key"
    # may take a **long** time to generate a key due to the
    # routine NOT being able to obtain enough system entropy.
    # Please see the "Performance Issues" sub-section under the
    # "Key Management" section in the following article
    # for an explanation as to why:
    #   https://pythonhosted.org/python-gnupg/   
    # on Linux systems, using "haveged" seems to ameloriate this:
    #   sudo apt-get install haveged
    # ---------------------------------------------------------------------
    
    print ("Generate a DSA key")

    dsa_data = gpg.gen_key_input(name_email=dsa_email_address,
                                    key_type=dsa_keyType,
                                    key_length=dsa_keyLength,
                                    key_usage=dsa_keyUsage,
                                    passphrase=dsa_passphrase)
    dsa_key = gpg.gen_key(dsa_data)
    print ("DSA Key: %s" % dsa_key.fingerprint)

    # ---------------------------------------------------------------------
    # Export keys to an ASCII-armored key file
    # ---------------------------------------------------------------------
    
    print ("Export the generated RSA and DSA keys")

    ascii_armored_public_keys = gpg.export_keys([rsa_email_address, dsa_email_address])
    ascii_armored_private_keys = gpg.export_keys([rsa_email_address, dsa_email_address], True)
    with open(gpgTestKeyFileNameExpanded, 'w') as f:
        f.write(ascii_armored_public_keys)
        f.write(ascii_armored_private_keys)        

    # ---------------------------------------------------------------------
    # Import keys from a key file
    # ---------------------------------------------------------------------

    print ("Import the RSA and DSA keys")
    
    key_data = open(gpgTestKeyFileNameExpanded).read()
    import_result = gpg.import_keys(key_data)
    print ('Import keys')
    pprint(import_result.results)

    # ---------------------------------------------------------------------
    # List both the public and private keys
    # ---------------------------------------------------------------------

    print ("List the RSA and DSA keys")
    
    public_keys = gpg.list_keys()
    private_keys = gpg.list_keys(True)

    print 'public keys:'
    pprint(public_keys)
    
    print 'private keys:'
    pprint(private_keys)
    
    # ---------------------------------------------------------------------
    # Encrypt and sign a string
    # ---------------------------------------------------------------------

    plaintext_string = 'Test the encryption and signing of a string #1'
    
    print ("Encrypt a plaintext string")    
    print (plaintext_string)
    
    encrypted_data = gpg.encrypt(plaintext_string,
                                 rsa_email_address,
                                 sign=dsa_email_address,
                                 passphrase=dsa_passphrase,
                                 armor=True)
    encrypted_string = str(encrypted_data)

    print ('Encrypt and sign a string')
    print 'ok: ', encrypted_data.ok
    print 'status: ', encrypted_data.status
    print 'stderr: ', encrypted_data.stderr
    print 'plaintext_string #1: ', plaintext_string
    print 'encrypted_string #1: ', encrypted_string
    
    # ---------------------------------------------------------------------
    # Decrypt an encrypted string
    # ---------------------------------------------------------------------

    encrypted_string = str(encrypted_data)

    print ("Decrypt an encrypted string")
    print (encrypted_string)
    
    decrypted_data = gpg.decrypt(encrypted_string, passphrase=rsa_passphrase)
    
    print ('Decrypt an encrypted string')
    print 'ok: ', decrypted_data.ok
    print 'status: ', decrypted_data.status
    print 'stderr: ', decrypted_data.stderr
    print 'decrypted string #1: ', decrypted_data.data
    
    # ---------------------------------------------------------------------
    # Sign the encrypted string
    # ---------------------------------------------------------------------

    encrypted_string = str(encrypted_data)
    
    print ("Sign an encrypted string")
    print (encrypted_string)
    
    sig = gpg.sign(encrypted_string,
                   keyid=dsa_email_address,
                   passphrase=dsa_passphrase,
                   binary=False)
    
    print ('Sign the encrypted string')
    print (sig.data)
    
    # ---------------------------------------------------------------------
    # Verify the signature of the encrypted string
    # ---------------------------------------------------------------------

    print ("Verify the signature of an encrypted string")
    print (sig.data)
    
    verified = gpg.verify(sig.data)
    
    print ('Verify the signature of the encrypted string')
    if verified:
        print ('DSA verified:\n %s' % sig.data)
    else:
        print ('DSA NOT verified:\n %s' % sig.data)
    
    # ---------------------------------------------------------------------
    # Encrypt and sign a text file asymmetrically
    # ---------------------------------------------------------------------

    print ("Asymmetrically encrypt and sign a text file")
    print ("TXT File: %s" % srcFileName)
    
    with open(srcFileNameExpanded, 'rb') as f:
        status = gpg.encrypt_file(f,
                                  recipients=[rsa_email_address],
                                  output=rsaFileName,
                                  sign=dsa_email_address,
                                  passphrase=dsa_passphrase,
                                  armor=rsa_ascii_armor)
    
    print ('Encrypt a file')
    print 'ok: ', status.ok
    print 'status: ', status.status
    print 'stderr: ', status.stderr
    
    # ---------------------------------------------------------------------
    # Detach-sign the encrypted-and-signed file
    # ---------------------------------------------------------------------

    print ("Asymmetrically detach-sign an encrypted file")
    print ("RSA File: %s" % rsaFileName)

    with open(rsaFileName, 'rb') as f:
        signed_data = gpg.sign_file(f,
                               keyid=dsa_email_address,
                               detach=True,
                               binary=False,
                               passphrase=dsa_passphrase)
        
    with open(dsaFileName, 'wb') as g:
        g.write(str(signed_data))
    
    print ('Detach-sign the encrypted file')
    print (str(signed_data))
    
    # ---------------------------------------------------------------------
    # Decrypt an encrypted file
    # ---------------------------------------------------------------------

    print ("Decrypt an encrypted file")
    print ("RSA File: %s" % rsaFileName)
    
    with open(rsaFileName, 'rb') as f:
        status = gpg.decrypt_file(f,
                                  passphrase=rsa_passphrase,
                                  output=srcFileNameExpanded)
    
    print ('Decrypt an encrypted file')
    print 'ok: ', status.ok
    print 'status: ', status.status
    print 'stderr: ', status.stderr

    # ---------------------------------------------------------------------
    # Verify a detach-signed file against its corresponding encrypted file
    # ---------------------------------------------------------------------

    print ("Verify a detach-signed file against its encrypted file")
    print ("DSA file: %s" % dsaFileName)
    print ("RSA file: %s" % rsaFileName)
    
    with open(dsaFileName, 'rb') as f:
        verified = gpg.verify_file(f, rsaFileName)
    
    print ('Verify a detach-signed file against the encrypted file')
    
    if verified:
        print ('DSA verified: %s' % dsaFileName)
        print ('RSA filename: %s' % rsaFileName)
    else:
        print ('DSA NOT verified: %s' % dsaFileName)
        print ('RSA filename: %s' % rsaFileName)

# -------------------------------------------------------------------------
# execute the "main" method
# -------------------------------------------------------------------------

if __name__ == "__main__":
    main()
