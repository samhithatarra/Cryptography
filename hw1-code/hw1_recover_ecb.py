import requests
import requests_cache
from datetime import timedelta


import config as cfg

BLOCK_BYTES = 16


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def ecb_encryption_oracle(pt: bytes) -> bytes:
    # Cache requests locally so that we don't have to hit the server for the same request multiple times.
    session = requests_cache.CachedSession(
        "ecb_oracle_cache", backend="sqlite", expire_after=timedelta(hours=2)
    )
    res = session.get(cfg.ECB_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:

    # TODO: fill in your answer here
    # length 6 is the greatest message input before another block is added-> ciphertext is 16 bytes
    # second block added 7, below is some code to find the pivot value so we can use it
    # one block is 16 bytes, 2 blocks are 32 bytes

    message_length = ""
    byte_length = len(ecb_encryption_oracle(message_length.encode()))
    byte_len_changed = False
    pivot = 0
    
    while byte_len_changed != True:
        message_length+="A"
        pivot+=1
        if len(ecb_encryption_oracle(message_length.encode())) > byte_length:
            byte_len_changed = True
    

    f = []
    # looping through message lengths to push one byte over to next block each time
    for i in range(1,BLOCK_BYTES-pivot+1):
        message = bytearray(pivot + i)
        ciphertext = ecb_encryption_oracle(message)

        # creating an array to manipulate
        test_message = bytearray(BLOCK_BYTES)

        # setting the values of the message to the correct "padding" value
        for j in range(i, BLOCK_BYTES):
            test_message[j] = BLOCK_BYTES-i


        # brute force all possibiltieis for the first value
        for byte_possibility in range(256):
            # setting first value to a possibility
            test_message[0] = byte_possibility

            # if we have parts of the flag we want to insert them
            f_counter = len(f)
            if len(f) > 0:
                for insert_ind in range(1,len(f)+1):
                    test_message[insert_ind] = f[f_counter-1]
                    f_counter-=1


            # run this test message through the oracle to see if it matches
            ct_temp = ecb_encryption_oracle(test_message)
            
            # if there is a match we append that byte value to our flag and break out of the loop
            if ct_temp[:BLOCK_BYTES] == ciphertext[-BLOCK_BYTES:]:
                f.append(byte_possibility)
                break
                            
        

    return bytes(f[::-1])

if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
