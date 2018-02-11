BASE32RFC4648   = "[^ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]"
ZBASE32         = "[^ybndrfg8ejkmcpqxot1uwisza345h769]"
CROCKFORDBASE32 = "[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]"
BASE64 = "[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]"
BITCOINBASE58 = "[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]"
UUENCODING = "[^ !\"#$%&'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]_^-]"
THEALPHABET = {'A':1, 'B':2, 'C':3, 'D':4, 'E':5, 'F':6, 'G':7, 'H':8, 'I':9,
'J':10, 'K':11, 'L':12, 'M':13, 'N':14, 'O':15, 'P':16, 'Q':17, 'R':18, 'S':19,
'T':20, 'U':21, 'V':22, 'W':23, 'X':24, 'Y':25, 'Z':26}
ALPHLOOKUP = {value:key for key,value in THEALPHABET.items()}

import re
from flask import request, render_template
from app import app

@app.route('/')
def my_form():
    return render_template('theInput.html')

@app.route('/', methods=['POST'])
def my_form_post():
    text = request.form['text']
    binaryText1 = caseSensitiveTextToBinary(text, flipped=False)
    binaryText2 = caseSensitiveTextToBinary(text, flipped=True)
        #For some reason, doing binaryText2 = flipBinary(binaryText1)
        #Causes binaryText1 to change its value to binaryText2...
    print(binaryText1)
    print(binaryText2)
    binaryToASCII1 = "Binary to ASCII 1: " + baseToASCII(binaryText1,2)
    binaryToASCII2 = "<br/>Binary to ASCII 2: " + baseToASCII(binaryText2,2)
    binaryToMorse1 = "<br/>Morse Decoder 1: " + binaryToMorseLetters(binaryText1)
    binaryToMorse2 = "<br/>Morse Decoder 2: " + binaryToMorseLetters(binaryText2)
    caesars = "<br/>Caesar Cipher Decoder: " + str(generateCaesarCiphers(text))
    octalDecrypted = "<br/>Octal Decoder: " + baseToASCII(text.split(),8)
    baseTenDecrypted = "<br/>Decimal Decoder: " + baseToASCII(text.split(),10)
    hexadecimalDecrypted = "<br/>Hexadecimal Decoder: " + baseToASCII(text.split(),16)
    base32HexDecrypted = "<br/>Base32Hex Decoder: " + baseToASCII(text.split(), 32)
    base32RFC4648Decrypted = "<br/>Base32 RFC 4648: " + decodeGeneral(text, BASE32RFC4648)
    zbase32Decrypted = "<br/>z-base-32: " + decodeGeneral(text, ZBASE32)
    crockfordBase32Decrypted = "<br/>Crockford's Base32: " + decodeGeneral(text, CROCKFORDBASE32)
    bitcoinBase58Decrypted = "<br/>Bitcoin's Base58: " + decodeGeneral(text,BITCOINBASE58)
    base64Decrypted = "<br/>Base64 Decoder: " + decodeGeneral(text, BASE64)
    uuencoding64Decrypted = "<br/>Uuencoding Base64 Decoder: " + decodeGeneral(text,UUENCODING)
    affineDecrypted = "<br/>Affine Cipher Decoder: " + str(generateAffineCiphers(text))
    letternumDecrypted = "<br/>Letter Number Decoder: " + letterNumberDecipher(text)

    response = (binaryToASCII1 + binaryToASCII2 + binaryToMorse1 + binaryToMorse2 +
    caesars + octalDecrypted + baseTenDecrypted + hexadecimalDecrypted + base32HexDecrypted +
    base32RFC4648Decrypted + zbase32Decrypted + crockfordBase32Decrypted + bitcoinBase58Decrypted
    + base64Decrypted + uuencoding64Decrypted + affineDecrypted + letternumDecrypted)

    return response

def uniqueCharacterCounter(str):
    thetest = re.sub(" ",'', str) #Remove spaces
    uniqueChars = []
    for c in thetest:
        if c not in uniqueChars:
            uniqueChars.append(c)
    return len(uniqueChars)

def uniqueCharacterFinder(str):
    thetest = re.sub(" ",'', str) #Remove spaces
    uniqueChars = []
    for c in thetest:
        if c not in uniqueChars:
            uniqueChars.append(c)
    return uniqueChars

#Converts lowercase to 0
#else converts uppercase to 1
#Returns a list of the transformed words
def caseSensitiveTextToBinary(str, flipped=False):
    if uniqueCharacterCounter(str)!=2:
        return ""

    #There are now guaranteed to be only two unique characters (and spaces)
    uniqueChars = uniqueCharacterFinder(str)
    words = str.split() #Split string if there are spaces
    for counter, word in enumerate(words):
        emptyString = ""
        for i, c in enumerate(word):
            print(c==uniqueChars[0])
            if c==uniqueChars[0]:
                if flipped:
                    emptyString += '1'
                else:
                    emptyString += '0'
            else:
                if flipped:
                    emptyString += '0'
                else:
                    emptyString += '1'
        words[counter] = emptyString #Change word
    return words

#Converts words to their ASCII equivalents
#thebase can vary depending on the base (usually 2,8,16,32,64)
#Returns a string
def baseToASCII(words, thebase):
    emptyString = ""
    words = ' '.join(words)
    words = words.upper()

    #The following follows RFC 3548 as per Python's standard
    #https://tools.ietf.org/html/rfc3548.html
    if thebase == 2 and bool(re.search("[^01 ]",words)):
        #If a character not 0 or 1 is found, it's obviously not binary
        return ""
    elif thebase == 4 and bool(re.search("[^0123 ]",words)):
        return ""
    elif thebase == 8 and bool(re.search("[^0-7 ]",words)):
        return ""
    elif thebase == 10 and bool(re.search("[^0-9 ]",words)):
        return ""
    elif thebase == 16 and bool(re.search("[^0-9A-F ]",words)):
        return ""
    elif thebase == 32 and bool(re.search("[^0-9A-V ]",words)): #Base32 Hex decoding
        return ""
    else: #Do nothing, this will never happen
        pass
    words = words.split()
    for word in words:
        lookup = 0
        try:
            lookup = int(word,base=thebase)
        except:
            return ""

        if lookup > 255: #If converted number is greater than 255, then dont map to ASCII. Instead just translate to base 10
            emptyString+= " " + str(lookup)
        else:
            emptyString+= chr(int(word,base=thebase))
    return emptyString

#Converts binary words to letters using Morse Code
#With - is 1, and . is 0
#Returns a string
def binaryToMorseLetters(words):
    CODE = {'A': '01',     'B': '1000',   'C': '1010',
        'D': '100',    'E': '0',      'F': '0010',
        'G': '110',    'H': '0000',   'I': '00',
        'J': '0111',   'K': '101',    'L': '0100',
        'M': '11',     'N': '10',     'O': '111',
        'P': '0110',   'Q': '1101',   'R': '010',
        'S': '000',    'T': '1',      'U': '001',
        'V': '0001',   'W': '011',    'X': '1001',
        'Y': '1011',   'Z': '1100',

        '0': '11111',  '1': '01111',  '2': '00111',
        '3': '00011',  '4': '00001',  '5': '00000',
        '6': '10000',  '7': '11000',  '8': '11100',
        '9': '11110',

        ',': '110011', '.': '010101', '?': '001100'
        }

    CODE_REVERSED = {value:key for key,value in CODE.items()}
    return ''.join(CODE_REVERSED.get(word, "") for word in words) #If not found, return ""

#Converts a Caesar Cipher encrypted message back into English
#code from https://inventwithpython.com/chapter14.html
#Returns a string
def caesarCipherDecrypt(message, yourkey):
    key = -1 * yourkey #Decrypting caesar cipher requires shifting letters back by your key
    translated = ''
    for symbol in message:
        if symbol.isalpha():
            num = ord(symbol)
            num += key

            if symbol.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif symbol.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26
            translated += chr(num)
        else:
            translated += symbol
    return translated

#Cycles through all keys for Caesar Cipher
#Returns a list of Strings on each key
def generateCaesarCiphers(message):
    caesars = []
    for i in range(1,27): #i goes from 1 to 26 inclusive
        caesars.append(caesarCipherDecrypt(message, i))
    return caesars


#https://stackoverflow.com/questions/1119722/base-62-conversion
def decodeGeneral(message, alphabet):
    #If something not in the alphabet is found...
    if bool(re.search(alphabet,message)):
        return "" # Just get out!!!
    words = message.split()
    for counter, word in enumerate(words):
        base = len(alphabet)
        strlen = len(word)
        num = 0

        idx = 0
        for char in word:
            power = (strlen - (idx + 1))
            num += alphabet.index(char) * (base ** power)
            idx += 1
        words[counter] = str(num)
    return baseToASCII(words, thebase=10)

#Decodes an Affine Cipher
def affineDecipher(message, keyA, keyB):
    message = message.upper()
    #Coprimes for finding the encoded character; see https://www.dcode.fr/affine-cipher
    coprimes = {1:1, 3:9, 5:21, 7:15, 9:3, 11:19, 15:7, 17:23, 19:11, 21:5, 23:17, 25:25}
    translated = ""
    coefficient = coprimes.get(keyA,0)
    for c in message:
        if c in THEALPHABET:
            newchar = chr((coefficient*(ord(c) - ord('A') - keyB) % 26) + ord('A'))
            translated+=newchar
        else:
            translated+= c
    return translated

#Cycles through all keys for Affine Cipher
#Returns a list of Strings on each key
def generateAffineCiphers(message):
    affines = []
    for keyA in [x for x in range(1,27, 2) if x!= 13]: #keyA is every other number from 1 to 25 inclusive, not including 13
        for keyB in range(0,26): #keyB is every number from 0 to 25
            affines.append(affineDecipher(message,keyA,keyB))
    return affines

#converts 1 to A, 2 to B, etc...
def letterNumberDecipher(message):
    #If not a number is found
    if bool(re.search("[^0-9 ]",message)):
        return "";
    words = message.split()
    translated = ""
    for word in words:
        translated+=ALPHLOOKUP.get(int(word),"")
    return translated
